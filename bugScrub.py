import json
import requests
import ssl
# import grpc
from cloudvision.Connector.codec import Wildcard
from cloudvision.Connector.grpc_client import GRPCClient, create_query
cvp_servers = ['192.168.255.50']
cvp_user = 'admin'
cvp_pass = 'Arista123'
tokenFile = 'token.txt'
certFile = 'cert.crt'

def login(url_prefix, username, password):
    connect_timeout = 10
    headers = {"Accept": "application/json",
           "Content-Type": "application/json"}
    session = requests.Session()
    authdata = {"userId": username, "password": password}
    response = session.post('https://'+url_prefix+'/web/login/authenticate.do', data=json.dumps(authdata),
                            headers=headers, timeout=connect_timeout,
                            verify=False)
    inventoryOutput = session.get('https://'+url_prefix+'/cvpservice/inventory/devices')#?provisioned=true')
    if response.json()['sessionId']:
        token = response.json()['sessionId']
        sslcert = ssl.get_server_certificate((url_prefix,8443))
        return [token,sslcert,inventoryOutput.json()]

def getBugs(client):
    pathElts = [
        "tags",
        "BugAlerts",
        "bugs"
    ]
    query = [create_query([(pathElts, [])], "analytics")]
    for notif in grpc_query(client, query):
        output = notif["updates"]
        return output

def getHostname(client,serialNumber):
    pathElts = [
        "Devices",
        serialNumber,
        "versioned-data",
        "Device"
    ]
    query = [create_query([(pathElts, [])], "analytics")]
    for notif in grpc_query(client, query):
        output = notif["updates"]
        return output

def getBugDetails(client,bugID):
    pathElts = [
        "BugAlerts",
        "bugs",
        bugID
    ]
    query = [create_query([(pathElts, [])], "analytics")]
    for notif in grpc_query(client, query):
        output = notif["updates"]
        return output

def main(server=None, token=None, certs=None, ca=None, key=None):
    for server in cvp_servers:
        creds = login(server, cvp_user, cvp_pass)
        inventory = creds[2]
        with open(tokenFile,"w") as f:
            f.write(creds[0])
            f.close()
        with open(certFile,"w") as f:
            f.write(creds[1])
            f.close()
        with GRPCClient(server+':8443', token=tokenFile, key=key, ca=certFile, certs=certs) as client:
            output = getBugs(client)
            #needs bugID specified as INT
            TotalBugs = []
            for bugID in output.keys():
                specificBug = getBugDetails(client,bugID)
                TotalBugs.append({bugID:specificBug})
        for bugtemp in TotalBugs:
                bugnumber = list(bugtemp)
                bug = bugtemp[bugnumber[0]]
                if bug['cve']:
                    print('===========================================================')
                    print('Bug Type: CVE')
                    print('Bug ID: '+str(bugnumber[0]))
                    print('CVE ID: '+str(bug['cve']))
                    print('Severity: '+str(bug['severity']))
                    print('version Introduced: '+str(bug['versionIntroduced']))
                    print('version Fixed: '+str(bug['versionFixed']))
                    affectedSwitches = output[bugnumber[0]]
                    hostlist = []
                    for switch in affectedSwitches:
                        for device in inventory:
                            if device['serialNumber'] == switch:
                                devHostname = device['hostname']
                                devVersion = device['version']
                                hostlist.append({devHostname:devVersion})
                    print('Affected Switches: '+str(hostlist))
                    print('Summary: '+str(bug['alertSummary']))
                    print('CVP IP: '+server)
                else:
                    pass
        for bugtemp in TotalBugs:
                bugnumber = list(bugtemp)
                bug = bugtemp[bugnumber[0]]
                print('===========================================================')
                print('Bug Type: BUG')
                print('Bug ID: '+str(bugnumber[0]))
                print('Severity: '+str(bug['severity']))
                print('version Introduced: '+str(bug['versionIntroduced']))
                print('version Fixed: '+str(bug['versionFixed']))
                affectedSwitches = output[bugnumber[0]]
                hostlist = []
                for switch in affectedSwitches:
                    for device in inventory:
                        if device['serialNumber'] == switch:
                            devHostname = device['hostname']
                            devVersion = device['version']
                            hostlist.append({devHostname:devVersion})
                print('Affected Switches: '+str(hostlist))
                print('Summary: '+str(bug['alertSummary']))
                print('CVP IP: '+server)


def grpc_query(client, query):
    for batch in client.get(query):
        yield from batch["notifications"]
if __name__ == "__main__":
        main()
