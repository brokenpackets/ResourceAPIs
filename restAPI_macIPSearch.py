import json
import requests
import ssl

cvp_servers = ['192.168.255.50']
cvp_user = 'admin'
cvp_pass = 'Arista123'
ip_to_search = '192.168.13.1'

def login(url_prefix, username, password):
    connect_timeout = 10
    headers = {"Accept": "application/json",
           "Content-Type": "application/json"}
    session = requests.Session()
    authdata = {"userId": username, "password": password}
    response = session.post('https://'+url_prefix+'/web/login/authenticate.do', data=json.dumps(authdata),
                            headers=headers, timeout=connect_timeout,
                            verify=False)
    if response.json()['sessionId']:
        token = response.json()['sessionId']
        return token

def search(server,token,ip_to_search):
    searchUrl = 'https://'+server+'/api/resources/endpointlocation/v1/EndpointLocation?key.search_term='+ip_to_search
    head = {'Authorization': 'Bearer {}'.format(token)}
    response = requests.get(searchUrl, headers=head, verify=False)
    return response.json()

def main(server=None, token=None, certs=None, ca=None, key=None):
    for server in cvp_servers:
        creds = login(server, cvp_user, cvp_pass)
        output = search(server,creds,ip_to_search)
        print output

if __name__ == "__main__":
        main()
