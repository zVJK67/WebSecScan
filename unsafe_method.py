import requests

url = "https://httpbin.org/anything"
resp = requests.options(url, allow_redirects=False)
print("Status:", resp.status_code)
print("Headers:", resp.headers)
print("Allow:", resp.headers.get("Allow"))
