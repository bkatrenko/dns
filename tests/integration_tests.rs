#[cfg(test)]
mod integration_tests {
    use dns;

    #[test]
    fn resolve_a() {
        let mut resolver = dns::create_resolver();

        let host_name = String::from("google.com");
        let record_type = String::from("A");
        let request_id = String::from("1");

        let question = dns::create_question(&host_name, &record_type);
        let res = dns::resolve(&mut resolver, question.to_bytes().unwrap(), &request_id);

        assert_eq!(res.is_err(), false);

        let response = res.unwrap();

        assert_eq!(response.response_part[0].name.value, "google.com");
        assert_eq!(response.response_part[0].record_class.to_string(), "IN");
        assert_eq!(response.response_part[0].record_type.to_string(), "A");
        assert!(response.response_part[0].data.to_string().starts_with("A { len: 4"));
    }

    #[test]
    fn resolve_aaaa() {
        let mut resolver = dns::create_resolver();

        let host_name = String::from("google.com");
        let record_type = String::from("AAAA");
        let request_id = String::from("1");

        let question = dns::create_question(&host_name, &record_type);
        let res = dns::resolve(&mut resolver, question.to_bytes().unwrap(), &request_id);

        assert_eq!(res.is_err(), false);

        let response = res.unwrap();

        assert_eq!(response.response_part[0].name.value, "google.com");
        assert_eq!(response.response_part[0].record_class.to_string(), "IN");
        assert_eq!(response.response_part[0].record_type.to_string(), "AAAA");
        assert!(response.response_part[0].data.to_string().starts_with("AAAA { len: 16"));
    }

    #[test]
    fn resolve_mx() {
        let mut resolver = dns::create_resolver();

        let host_name = String::from("google.com");
        let record_type = String::from("MX");
        let request_id = String::from("1");

        let question = dns::create_question(&host_name, &record_type);
        let res = dns::resolve(&mut resolver, question.to_bytes().unwrap(), &request_id);

        assert_eq!(res.is_err(), false);

        let response = res.unwrap();

        assert_eq!(response.response_part[0].name.value, "google.com");
        assert_eq!(response.response_part[0].record_class.to_string(), "IN");
        assert_eq!(response.response_part[0].record_type.to_string(), "MX");
        assert!(response.response_part[0].data.to_string().starts_with("MX { len: 9"));
    }

    #[test]
    fn resolve_txt() {
        let mut resolver = dns::create_resolver();

        let host_name = String::from("korrespondent.net");
        let record_type = String::from("TXT");
        let request_id = String::from("1");

        let question = dns::create_question(&host_name, &record_type);
        let res = dns::resolve(&mut resolver, question.to_bytes().unwrap(), &request_id);

        assert_eq!(res.is_err(), false);

        let response = res.unwrap();

        assert_eq!(response.response_part.len(), 3);
        assert_eq!(response.response_part[0].name.value, "korrespondent.net");
        assert_eq!(response.response_part[0].record_class.to_string(), "IN");
        assert_eq!(response.response_part[0].record_type.to_string(), "TXT");
        assert!(response.response_part[0].data.to_string().starts_with("TXT"));
        assert!(response.response_part[1].data.to_string().starts_with("TXT"));
        assert!(response.response_part[2].data.to_string().starts_with("TXT"));
    }

    #[test]
    fn resolve_cname() {
        let mut resolver = dns::create_resolver();

        let host_name = String::from("en.wikipedia.org");
        let record_type = String::from("CNAME");
        let request_id = String::from("1");

        let question = dns::create_question(&host_name, &record_type);
        let res = dns::resolve(&mut resolver, question.to_bytes().unwrap(), &request_id);

        assert_eq!(res.is_err(), false);

        let response = res.unwrap();

        assert_eq!(response.response_part.len(), 2);
        assert!(response.response_part[0].data.to_string().starts_with("CNAME"));
        assert!(response.response_part[1].data.to_string().starts_with("A"));
    }
}
