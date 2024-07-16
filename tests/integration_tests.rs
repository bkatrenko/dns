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
        assert_eq!(
            response.response_part[0].data.to_string(),
            "A { len: 4, ip: 142.251.209.142 }"
        )
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
        assert_eq!(
            response.response_part[0].data.to_string(),
            "AAAA { len: 16, ip: 2a00:1450:4005:801::200e }"
        )
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
        assert_eq!(
            response.response_part[0].data.to_string(),
            "MX { len: 9, priority: 10, host: \"smtp.google.com\" }"
        )
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
        assert_eq!(
            response.response_part[0].data.to_string(), 
            "TXT { len: 69, data: \"google-site-verification=CFcAoeqNeHl3uc-VCQkjOZ9EF1Utcn0J9x7bThF7SM4\" }",
        );
        assert_eq!(
            response.response_part[1].data.to_string(),
            "TXT { len: 32, data: \"v=spf1 ip4:193.29.200.0/24 ~all\" }"
        );
        assert_eq!(
            response.response_part[2].data.to_string(),
            "TXT { len: 38, data: \"yandex-verification: 67c648566e370b6d\" }"
        );
    }
}
