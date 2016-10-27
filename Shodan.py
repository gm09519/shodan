import shodan
import sys
import csv
import re
# Configuration
API_KEY = "API Key"

try:
	# Setup the api
	api = shodan.Shodan(API_KEY)
	set=[];
	result=[];
	name='';
	brands=["<query>"]
	out=open("new_data.csv","w")
	output=csv.writer(out)
	# Perform the search
	for query in brands:
		result = api.search(query)
		print (result['total'])
		# Loop through the matches and print each IP
		for res in result['matches']:
			#print (res)
			try:
				ip = res['ip_str']
				service = api.host(ip)
				details = service['data']
				set=[];
				name='';
				#print (service)
				hostname = service['hostnames']
				try:
					host = service['http']['host']
				except:
					try:
						host = service['data'][0]['url']
					except:
						host = "N/A"
				try:
					vuln = service['vulns']
				except:
					vuln = "N/A"
				try:
					os = service['os']
				except:
					os = "N/A"
				try:
					port = service['ports']
				except:
					port = "N/A"
				try:
					device = service['data'][0]['devicetype']
				except:
					device = "N/A"
				try:
					location = service['data'][0]['location']['country_name']
				except:
					location = "N/A"
				try:
					product = service['data'][0]['product']
				except:
					product = "N/A"
				try:
					server = service['data'][0]['http']['server']
				except:
					server = "N/A"
				try:
					title = service['data'][0]['title']
				except:
					title = "N/A"
				try:
					lastupdated = service['data'][0]['timestamp']
				except:
					lastupdated = "N/A"
				try:
					cn = service['ssl']['cert']['subject']['CN']
				except:
					cn = "N/A"
				try:
					expires = service['ssl']['cert']['expires']
				except:
					expires = "N/A"
				try:
					expired = service['ssl']['cert']['expired']
				except:
					expired= "N/A"
				set.append(ip)
				set.append(hostname)
				set.append(os)
				set.append(vuln)
				set.append(port)
				set.append(device)
				set.append(server)
				set.append(product)
				set.append(title)
				set.append(cn)
				set.append(expires)
				set.append(expired)
				set.append(location)
				set.append(lastupdated)
				output.writerow(set)
				print(set)
			except:
				print ("error")
		#for row in service
	#end of brands
	out.close()
except Exception as e:
	print ('Error: %s' % e)
	sys.exit(1)
