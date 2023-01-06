import requests
import argparse

def scan_url(url, rate_limit, headers, cookies, params):
    """Scans the specified URL for RCE vulnerabilities using the given headers, cookies, and parameters.
    
    Arguments:
        url {str} -- The URL to scan.
        rate_limit {float} -- The rate limit time in seconds.
        headers {list} -- A list of dictionaries containing HTTP headers to scan.
        cookies {list} -- A list of dictionaries containing cookies to scan.
        params {list} -- A list of dictionaries containing parameters to scan.
    
    Returns:
        bool -- True if a possible RCE vulnerability was detected, False otherwise.
    """
    # Scan each combination of headers, cookies, and parameters
    for header in headers:
        for cookie in cookies:
            for param in params:
                print(f"Scanning with header: {header}, cookie: {cookie}, param: {param}")

                # Add a payload to the headers to make the server sleep for the rate limit time
                # Add a payload to the headers to make the server sleep for the rate limit time
                header["X-Sleep"] = f"sleep({rate_limit})"

                # Send a GET request with the modified headers, cookies, and parameters
                response = requests.get(url, headers=header, cookies=cookie, params=param)
                 # Get the elapsed time of the request
                elapsed_time = response.elapsed.total_seconds()

                # If the elapsed time is greater than the rate limit, it could be an indication of an RCE vulnerability
                if elapsed_time > rate_limit:
                    print("Possible RCE vulnerability detected!")
                    return True
                else:
                    print("No RCE vulnerabilities detected.")
     

    print("No RCE vulnerabilities detected.")
    return False

if __name__ == "__main__":
    # Create a command line argument parser
    parser = argparse.ArgumentParser()

    # Add a command line argument for the URL to scan
    parser.add_argument("url", help="The URL to scan for RCE vulnerabilities")

    # Add a command line argument for the rate limit time
    parser.add_argument("-l", "--limit", type=float, default=1.0, help="The rate limit time in seconds")

    # Parse the command line arguments
    args = parser.parse_args()

    # Set the URL to scan
    url = args.url

    # Set the rate limit (in seconds)
    rate_limit = args.limit

    # Set the HTTP headers to scan
    headers = [
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close"
        },
        {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close"
        },
        {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close"
        }
    ]

    # Set the cookies to scan
    cookies = [
        {
            "session_id": "123456"
        },
        {
            "session_id": "abcdef"
        },
        {
            "session_id": "zyxwv"
        }
    ]

    # Set the parameters to scan
    params = [
        {
            "param1": "value1",
            "param2": "value2"
        },
        {
            "param1": "value3",
            "param2": "value4"
        },
        {
            "param1": "value5",
            "param2": "value6"
        }
    ]

    # Scan the URL for RCE vulnerabilities
    rce_detected = scan_url(url, rate_limit, headers, cookies, params)

    if rce_detected:
        print("RCE vulnerabilities detected. Please consult a security expert for further assistance.")
    else:
        print("No RCE vulnerabilities detected.")

