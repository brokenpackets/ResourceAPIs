curl -sS -kX GET --header 'Accept: application/json' -b access_token=`cat newtoken.txt` 'https://192.168.255.50/api/resources/endpointlocation/v1/EndpointLocation?key.search_term=192.168.13.1'
