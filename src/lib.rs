use log::error;

pub fn match_lines(content: &str, pattern: &str, mut writer: impl std::io::Write) {
    for line in content.lines() {
        if line.contains(pattern) {
            let result  = writeln!(writer, "{}", line);
            match result {
                Err(e) => { 
                    error!("Error matching lines: {}", e);
                }
                Ok(()) => { 
                    // noop 
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_text(){
        let mut result = Vec::new();
        match_lines("the\nbig\nbad\nwolf", "bad", &mut result);
        assert_eq!(result, b"bad\n")

    }
}