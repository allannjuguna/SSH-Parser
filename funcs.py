from collections import Counter
import re


verbose="False"
white="\033[0m"
red="\033[91m"
green="\033[92m"
bold="\033[01m"
yellow="\033[93m"
blue="\033[94m"
success=f"{bold}{green}[+]{white} - "
alert=f"{bold}{yellow}[!]{white} - "
progress=f"{bold}{blue}[*]{white} - "
fail=f"{bold}{red}[*]{white} - "
end=f"{white}"
padding=17

count=10000000000



def load_file(filename):
	# Check if the file is readable
	logs=[]
	try:
		r=open(filename,'r', encoding="latin-1")
		logs=[log.strip() for log in r.readlines() if log]
		r.close()
	except PermissionError:
		print(f"{fail} You need to be root to access '{filename}'")
	except FileNotFoundError:
		print(f"{fail} Could not open file '{filename}'")
	except Exception as e:
		print(f"An error occurred while reading the file. Error {e}")
	return logs


def failed_sshkey_connections(logs):
	failed_negotiation_analytics=[]
	"""
	Find failed ssh key negotiations, could be attackers without valid ssh key
	"""
	for line in logs:
		if 'Unable to negotiate ' in line:
			# username,source_ip="unknown",line.split(' ')[9].replace("'","")
			source_ip=re.findall("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",line)[0]
			username,_="unknown",line.split(' ')[9].replace("'","")
			# failed_negotiation_analytics.append(f"{bold}{red}{username.ljust(padding,' ')}{end} - source_ip = {bold}{red}{source_ip}{end}")
			failed_negotiation_analytics.append(f'{username} : {source_ip}')

	return failed_negotiation_analytics


def password_sprays(logs):
	password_spray_analytics=[]
	"""
	Find login attempts with correct usernames and wrong passwords
	"""
	for line in logs:
		if ': Failed password for ' in line and 'invalid' not in line:
			username,source_ip=line.split(' ')[-6],line.split(' ')[-4]
			# password_spray_analytics.append(f"{yellow}{username.ljust(padding,' ')}{end} - source_ip = {bold}{red}{source_ip}{end}")
			password_spray_analytics.append(f'{username} : {source_ip}')
	return password_spray_analytics

def show_count(array):
	arr=[]
	counter=Counter(array)
	for key,value in counter.most_common(count):
		# print(f"{key} - Appeared {value} times")
		try:
			arr.append({
				"Username": key.split(' : ')[0],
				"Source": key.split(' : ')[1],
				"Count": int(value),
				})
		except:
			arr.append({
				"Source": key,
				"Count": int(value),
				})

	return arr


def successful_logins(logs):
	"""
	Find successful logins from all logs
	"""
	successful_analytics=[]
	for line in logs:
		if 'Accepted password for ' in line or 'Accepted publickey for ' in line:
			# pass
			username,source_ip=line.split(' ')[9],line.split(' ')[11]
			if 'from' in username:
				username,source_ip=line.split(' ')[8],line.split(' ')[10]
			# successful_analytics.append(f"{green}{username.ljust(padding,' ')}{end} - {source_ip}")
			successful_analytics.append(f'{username} : {source_ip}')

	return successful_analytics

def bruteforce_attempts(logs):
	bruteforce_analytics=[]
	"""
	Find bruteforce attempts from all logs. These are logins with invalid username and invalid password
	"""
	for line in logs:
		if ': Invalid user ' in line:
			username,source_ip=line.split(' ')[8],line.split(' ')[10].replace("'","")
			if 'from' in username:
				username,source_ip=line.split(' ')[7],line.split(' ')[9]
			# bruteforce_analytics.append(f"{bold}{red}{username.ljust(padding,' ')}{end} - source_ip = {bold}{red}{source_ip}{end}")
			bruteforce_analytics.append(f'{username} : {source_ip}')

	return bruteforce_analytics


def last_successful_logins(logs):
	result=[]
	"""
	Find successful logins from all logs
	"""
	# print(f"\n\n{progress} Last {count} successful Logins")
	result.append('\n'.join([(line) for line in logs if 'Accepted password for ' in line][-count::]))
	result.append('\n'.join([(line) for line in logs if 'Accepted publickey for ' in line][-count::]))
	return [i for i in result if len(i)] # remove empty items