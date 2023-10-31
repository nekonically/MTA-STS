import dns.resolver
import pandas
import requests
import concurrent.futures

def get_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            return str(rdata.target)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.name.EmptyLabel):
        return None
    except(dns.resolver.LifetimeTimeout):
        return None

def get_mxrecord(domain):
    try:
        answer = dns.resolver.resolve(domain, 'MX')
        return answer
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.name.EmptyLabel):
        return None
    except(dns.resolver.LifetimeTimeout):
        return None

def get_mtasts_txt_record(domain):
    try:
        answer = dns.resolver.resolve("_mta-sts."+domain, 'TXT')
        return '; '.join(str(rdata) for rdata in answer).replace("\"","")


    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.name.EmptyLabel):
        return None
    except(dns.resolver.LifetimeTimeout):
        return None
    except Exception as e:
        print(f"Error fetching TXT record for {domain}: {e}")
        return None

def checklf(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

        if '\r\n' not in content and '\r' not in content:
            print(f"The file {file_path} uses only LF as line ending.")
        else:
            print(f"The file {file_path} does not use only LF as line ending.")

def validate_mta_sts_string(s: str) -> bool:
    # Split by semicolon
    pairs = s.split(";")

    # Extract key-value pairs
    kv = {}
    for pair in pairs:
        if '=' in pair:
            key, value = pair.strip().split('=', 1)
            kv[key] = value

    # Verify "v" key
    if 'v' not in kv or kv['v'] != "STSv1":
        return False

    # Verify "id" key exists
    if 'id' not in kv:
        return False

    return True




def fetch_mta_sts(domain):
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    validation_results = {
        "content_type": None,
        "charset": None,
        "version": None,
        "mode": None,
        "max_age": None,
        "mx": None,
        "mx_matches_global": False,
        "crlf": None,  # To validate CRLF
        "response_text": None,  # The entire response text
        "compliant": False  # Initial value
    }

    try:
        response = requests.get(url,verify=False)

        # Add the entire response text
        validation_results["response_text"] = response.text

        # Validate CRLF
        validation_results["crlf"] = '\r\n' in response.text

        # Check content type
        content_type = response.headers.get('Content-Type', '')
        validation_results["content_type"] = 'text/plain' in content_type or content_type

        # Check charset
        charset_valid = 'charset=utf-8' in response.encoding or 'charset=us-ascii' in response.encoding
        validation_results["charset"] = charset_valid or response.encoding

        # Split the policy by lines and create a dictionary of key/value pairs
        policy = {}
        for line in response.text.splitlines():
            key, _, value = line.partition(":")
            policy.setdefault(key.strip(), []).append(value.strip())

        # Validate version
        validation_results["version"] = True if policy.get("version") == ["STSv1"] else \
        policy.get("version", [None])[0]

        # Validate mode
        mode = policy.get("mode", [None])[0]
        validation_results["mode"] = True if mode in ["enforce", "testing", "none"] else mode

        # Validate max_age
        max_age = policy.get("max_age", [None])[0]
        if max_age and max_age.isdigit() and int(max_age) <= 31557600:
            validation_results["max_age"] = True
        else:
            validation_results["max_age"] = max_age

        # Validate mx values
        validation_results["mx"] = policy.get("mx", [None])

        mxrecord = get_mxrecord(domain)
        mxrecord_string = [str(r.exchange) for r in mxrecord]
        validation_results["mx_matches_global"] = set(mxrecord_string) == set(validation_results["mx"])
        # Check if all values comply
        validation_results["compliant"] = all(
            (isinstance(val, list) or val is True or val in ["STSv1", "enforce", "testing", "none"])
            for val in validation_results.values() if val != validation_results["response_text"]  or val != validation_results["mx_matches_global"]
        )

        return validation_results

    except Exception as e:
        # Handle exceptions
        return {"error": str(e)}


def process_domain(domain_info):
    count, line = domain_info
    record = {
        "#": count,
        "Domain": line,
        "MX": False,
        "MX records": False,
        "MTA-STS TXT": None,
        "MTA-STS TXT VALIDATION": None,
        "MTA-STS HTTP": None,
        "MTA-STS HTTP VALIDATION": None
    }

    mx_record = get_mxrecord(line)


    if mx_record:
        record.update({"MX": True if mx_record else False})
        mx_list = [r.to_text() for r in mx_record]
        record.update({"MX records": mx_list if mx_record else False})


        mtasts_txt_record = get_mtasts_txt_record(line)
        if mtasts_txt_record:
            record.update({"MTA-STS TXT": mtasts_txt_record if mx_record else None})

            isMTASTSrecordValid = validate_mta_sts_string(mtasts_txt_record)
            record.update({"MTA-STS TXT VALIDATION": True if isMTASTSrecordValid else False})

            MTASTSPolicy = fetch_mta_sts(line)
            record.update({"MTA-STS HTTP": MTASTSPolicy})
    if record.get('MTA-STS TXT'):
        print(record)
    return record

def main():
    filename = "free_email_provider_domains.txt"

    checklf(filename)

    with open(filename, 'r') as file:
        lines = file.read().splitlines()  # Split lines and remove potential newline at the end
        print("Total Lines : " + str(len(lines)))

    # Placeholder for data to be added to DataFrame
    data = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        data = list(executor.map(process_domain, enumerate(lines, start=1)))


    df = pandas.DataFrame(data)
    df.to_csv("analysis.csv")


if __name__ == "__main__":
    main()
