use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, ExitCode};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Listener {
    protocol: String,
    address: String,
    state: String,
    pid: Option<u32>,
    process: Option<String>,
}

#[cfg_attr(windows, allow(dead_code))]
fn parse_pid(text: &str) -> Option<u32> {
    if let Some(start) = text.find("pid=") {
        return text[start + 4..]
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok();
    }
    None
}

#[cfg_attr(windows, allow(dead_code))]
fn parse_process(text: &str) -> Option<String> {
    let start = text.find("((\"")? + 3;
    let rest = &text[start..];
    Some(rest.split('"').next()?.to_owned())
}

#[cfg_attr(windows, allow(dead_code))]
fn parse_ss(output: &str) -> Vec<Listener> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                return None;
            }
            let protocol = fields[0].to_ascii_lowercase();
            if !protocol.starts_with("tcp") && !protocol.starts_with("udp") {
                return None;
            }
            Some(Listener {
                protocol,
                state: fields[1].to_owned(),
                address: fields[4].to_owned(),
                pid: parse_pid(line),
                process: parse_process(line),
            })
        })
        .collect()
}

fn parse_netstat(output: &str) -> Vec<Listener> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.is_empty() {
                return None;
            }
            let protocol = fields[0].to_ascii_lowercase();
            if !protocol.starts_with("tcp") && !protocol.starts_with("udp") {
                return None;
            }
            if cfg!(windows) {
                if protocol.starts_with("tcp") && fields.len() >= 5 {
                    if !fields[3].eq_ignore_ascii_case("LISTENING") {
                        return None;
                    }
                    return Some(Listener {
                        protocol,
                        address: fields[1].to_owned(),
                        state: fields[3].to_owned(),
                        pid: fields[4].parse().ok(),
                        process: None,
                    });
                }
                if protocol.starts_with("udp") && fields.len() >= 4 {
                    return Some(Listener {
                        protocol,
                        address: fields[1].to_owned(),
                        state: "UNCONN".to_owned(),
                        pid: fields[3].parse().ok(),
                        process: None,
                    });
                }
            } else if fields.len() >= 4 {
                return Some(Listener {
                    protocol,
                    address: fields[3].to_owned(),
                    state: fields.get(5).unwrap_or(&"UNCONN").to_string(),
                    pid: None,
                    process: None,
                });
            }
            None
        })
        .collect()
}

fn collect() -> io::Result<Vec<Listener>> {
    type Probe<'a> = (&'a str, &'a [&'a str], fn(&str) -> Vec<Listener>);
    #[cfg(windows)]
    let attempts: &[Probe<'_>] = &[("netstat", &["-ano"], parse_netstat)];
    #[cfg(not(windows))]
    let attempts: &[Probe<'_>] = &[
        ("ss", &["-H", "-lntup"], parse_ss),
        ("netstat", &["-lntu"], parse_netstat),
    ];

    for (program, args, parser) in attempts {
        match Command::new(program).args(*args).output() {
            Ok(output) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut listeners = parser(&text);
                listeners.sort();
                listeners.dedup();
                return Ok(listeners);
            }
            _ => continue,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "neither ss nor netstat produced a listener inventory",
    ))
}

fn clean_field(value: &str) -> String {
    value.replace(['\t', '\r', '\n'], " ")
}

fn save_baseline(path: &Path, listeners: &[Listener]) -> io::Result<()> {
    let mut text = String::from("# dispersal-wolves/open-ports/v1\n");
    for item in listeners {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            clean_field(&item.protocol),
            clean_field(&item.address),
            clean_field(&item.state),
            item.pid.map(|value| value.to_string()).unwrap_or_default(),
            clean_field(item.process.as_deref().unwrap_or(""))
        ));
    }
    fs::write(path, text)
}

fn load_baseline(path: &Path) -> io::Result<Vec<Listener>> {
    let text = fs::read_to_string(path)?;
    if !text.starts_with("# dispersal-wolves/open-ports/v1\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported baseline format",
        ));
    }
    text.lines()
        .skip(1)
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() != 5 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid baseline row",
                ));
            }
            Ok(Listener {
                protocol: fields[0].to_owned(),
                address: fields[1].to_owned(),
                state: fields[2].to_owned(),
                pid: if fields[3].is_empty() {
                    None
                } else {
                    fields[3].parse().ok()
                },
                process: if fields[4].is_empty() {
                    None
                } else {
                    Some(fields[4].to_owned())
                },
            })
        })
        .collect()
}

fn json_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            c if c.is_control() => format!("\\u{:04x}", c as u32).chars().collect(),
            c => vec![c],
        })
        .collect()
}

fn render_json(listeners: &[Listener]) -> String {
    let rows = listeners.iter().map(|item| format!(
        "{{\"protocol\":\"{}\",\"address\":\"{}\",\"state\":\"{}\",\"pid\":{},\"process\":{}}}",
        json_escape(&item.protocol), json_escape(&item.address), json_escape(&item.state),
        item.pid.map(|value| value.to_string()).unwrap_or_else(|| "null".into()),
        item.process.as_ref().map(|value| format!("\"{}\"", json_escape(value))).unwrap_or_else(|| "null".into())
    )).collect::<Vec<_>>().join(",");
    format!("{{\"schema\":\"dispersal-wolves/open-ports/v1\",\"listeners\":[{rows}]}}")
}

fn render_json_array(listeners: &[Listener]) -> String {
    let document = render_json(listeners);
    document
        .split_once("\"listeners\":")
        .and_then(|(_, tail)| tail.strip_suffix('}'))
        .unwrap_or("[]")
        .to_owned()
}

fn render_table(listeners: &[Listener]) -> String {
    let mut output = format!(
        "{:<8} {:<32} {:<12} {:<8} {}\n",
        "PROTO", "LOCAL ADDRESS", "STATE", "PID", "PROCESS"
    );
    for item in listeners {
        output.push_str(&format!(
            "{:<8} {:<32} {:<12} {:<8} {}\n",
            item.protocol,
            item.address,
            item.state,
            item.pid
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            item.process.as_deref().unwrap_or("-")
        ));
    }
    output
}

fn option(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|value| value == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn usage() {
    eprintln!(
        "Usage:\n  open-ports scan [--format table|json]\n  open-ports baseline --output FILE\n  open-ports diff --baseline FILE [--format table|json]"
    );
}

fn run(args: &[String]) -> Result<u8, String> {
    let Some(command) = args.first().map(String::as_str) else {
        usage();
        return Ok(2);
    };
    match command {
        "scan" => {
            let listeners = collect().map_err(|error| error.to_string())?;
            let format = option(args, "--format").unwrap_or_else(|| "table".into());
            println!(
                "{}",
                if format == "json" {
                    render_json(&listeners)
                } else if format == "table" {
                    render_table(&listeners)
                } else {
                    return Err("format must be table or json".into());
                }
            );
            Ok(0)
        }
        "baseline" => {
            let output = option(args, "--output").ok_or("baseline requires --output FILE")?;
            let listeners = collect().map_err(|error| error.to_string())?;
            save_baseline(Path::new(&output), &listeners).map_err(|error| error.to_string())?;
            println!("Saved {} listeners to {}", listeners.len(), output);
            Ok(0)
        }
        "diff" => {
            let baseline_path =
                option(args, "--baseline").ok_or("diff requires --baseline FILE")?;
            let baseline =
                load_baseline(Path::new(&baseline_path)).map_err(|error| error.to_string())?;
            let current = collect().map_err(|error| error.to_string())?;
            let before: BTreeSet<_> = baseline.into_iter().collect();
            let after: BTreeSet<_> = current.into_iter().collect();
            let added: Vec<_> = after.difference(&before).cloned().collect();
            let removed: Vec<_> = before.difference(&after).cloned().collect();
            let format = option(args, "--format").unwrap_or_else(|| "table".into());
            if format == "json" {
                println!(
                    "{{\"schema\":\"dispersal-wolves/open-ports-diff/v1\",\"added\":{},\"removed\":{}}}",
                    render_json_array(&added),
                    render_json_array(&removed)
                );
            } else if format == "table" {
                println!(
                    "ADDED ({})\n{}\nREMOVED ({})\n{}",
                    added.len(),
                    render_table(&added),
                    removed.len(),
                    render_table(&removed)
                );
            } else {
                return Err("format must be table or json".into());
            }
            Ok(u8::from(!added.is_empty()))
        }
        _ => {
            usage();
            Ok(2)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("Open Ports: {message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ss_output() {
        let rows =
            parse_ss("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=42,fd=3))\n");
        assert_eq!(rows[0].address, "0.0.0.0:22");
        assert_eq!(rows[0].pid, Some(42));
        assert_eq!(rows[0].process.as_deref(), Some("sshd"));
    }

    #[test]
    fn windows_netstat_parser_excludes_established_tcp() {
        let rows = parse_netstat(
            "  TCP    0.0.0.0:22    0.0.0.0:0    LISTENING    42\n  TCP    127.0.0.1:5000    127.0.0.1:6000    ESTABLISHED    43\n  UDP    0.0.0.0:53    *:*    44\n",
        );
        if cfg!(windows) {
            assert_eq!(rows.len(), 2);
            assert!(rows.iter().all(|row| row.pid != Some(43)));
        }
    }

    #[test]
    fn baseline_round_trip() {
        let path = env::temp_dir().join(format!("open-ports-{}.dw", std::process::id()));
        let listeners = vec![Listener {
            protocol: "tcp".into(),
            address: "127.0.0.1:80".into(),
            state: "LISTEN".into(),
            pid: Some(1),
            process: Some("server".into()),
        }];
        save_baseline(&path, &listeners).unwrap();
        assert_eq!(load_baseline(&path).unwrap(), listeners);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn json_escapes_control_characters() {
        assert_eq!(json_escape("a\n\"b"), "a\\n\\\"b");
    }
}
