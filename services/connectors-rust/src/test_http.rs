use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

pub fn server(responses: Vec<String>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let response_origin = origin.clone();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for reply in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut bytes = [0; 8192];
                let size = stream.read(&mut bytes).unwrap();
                assert!(size > 0);
                request.extend_from_slice(&bytes[..size]);
                assert!(request.len() <= 65536);
                if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length = headers
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8_lossy(&request).to_string());
            let resolved = reply.replace("{ORIGIN}", &response_origin);
            let (headers, body) = resolved.split_once("\r\n\r\n").unwrap();
            let headers = headers
                .lines()
                .map(|line| {
                    if line.starts_with("Content-Length:") {
                        format!("Content-Length: {}", body.len())
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\r\n");
            stream
                .write_all(format!("{headers}\r\n\r\n{body}").as_bytes())
                .unwrap();
        }
        requests
    });
    (origin, handle)
}
pub fn response(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len()
    )
}
