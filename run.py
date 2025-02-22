import os
import re
import csv
import shutil
import json
import asyncio
import tempfile
import subprocess
import requests
import time
import hashlib
import zipfile
import platform

requests.packages.urllib3.disable_warnings()

# md5
def md5(msg, encoding='utf8'):
    return hashlib.md5(msg.encode(encoding)).hexdigest()

# 从文件中读取GitHub项目链接
def read_github_links(file_path):
    links = []
    # 读取CSV文件
    with open(file_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # 跳过标题行
        for row in reader:
            if row[0].startswith('https://github.com'):
                links.append(row[0])  # 提取链接并添加到列表中
    return links

# 追加写入GitHub项目链接
def append_github_links(file_path, links):
    # 追加链接到CSV文件
    with open(file_path, 'a', newline='') as f:
        writer = csv.writer(f)
        for link in links:
            writer.writerow([link])  # 写入链接

# 搜索项目
def search_projects():
    token = os.getenv("GH_TOKEN", "")
    headers = {
        "Authorization": f"{token}",
        "Connection": "close",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.119 Safari/537.36",
    }
    # Send a search request to GitHub API
    search_url = "https://api.github.com/search/repositories?q=nuclei-templates&sort=updated&page=1&per_page=100"
    response = requests.get(search_url, headers=headers,
                            verify=False, allow_redirects=False).json()
    print(response)

    # Extract the list of projects from the response
    projects = [i['html_url'] for i in response.get("items", [])]

    # Return the list of projects
    return projects

# 校验yaml文件
def nuclei_validate(temp_directory):
    # 当前目录路径
    current_directory = os.path.join(os.getcwd(),'nuclei-templates')
    nuclei_path = download_extract_executable(temp_directory)
    command = f'{nuclei_path} -validate -t {current_directory}'
    try:
        output = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        output = e.output
    err_pattern = r"Error occurred (?:loading|parsing) template (.*?)\:"
    for err_match in re.findall(err_pattern, output):
        file_path = err_match.replace("\\", "/")  # 转换文件路径中的反斜杠
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Deleted file: {file_path}")
    warn_pattern = r"Found duplicate template ID during validation '(.*?)' => '(.*?)'\:"
    for warn_match in re.findall(warn_pattern, output):
        old_path = warn_match[0].replace("\\", "/")
        new_path = warn_match[1].replace("\\", "/")
        if os.path.exists(old_path):
            shutil.move(old_path, new_path)
            print(f"Renamed file: {old_path} to {new_path}")

# 下载nuclei
def download_extract_executable(temp_directory):
    system = platform.system()
    if system == 'Windows':
        zip_file_path = './nuclei/nuclei_3.3.5_windows_amd64.zip'
    else:
        zip_file_path = './nuclei/nuclei_3.3.5_linux_amd64.zip'

    # 解压压缩包
    extract_dir = os.path.join(temp_directory, "extracted")
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

    # 添加执行权限
    for executable in os.listdir(extract_dir):
        if 'nuclei' in executable:
            executable_path = os.path.join(extract_dir, executable)
            os.chmod(executable_path, 0o755)
            print(executable_path)
    # 返回可执行文件的完整路径
    return executable_path

# 遍历临时目录中的.yaml文件
def process_yaml_files(temp_directory):
    # 创建目标文件夹
    target_directory = os.path.join(os.getcwd(),'nuclei-templates', 'Other')
    os.makedirs(target_directory, exist_ok=True)

    # 遍历临时目录
    for root, _, files in os.walk(temp_directory):
        for file in files:
            if file.endswith('.yaml'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf8') as f:
                        content = f.read()
                except:
                    continue

                # 判断文件内容是否包含关键字
                if len([tag for tag in ['id:', 'info:', 'name:', 'author:', 'severity:', 'description:', 'tags:', 'requests:', 'matchers:'] if tag in content]) > 5:
                    # 判断文件名是否匹配CVE-\d{4}
                    match1 = re.match(r'CVE-\d{4}', file, re.I)
                    # tags: cve,wordpress,wp-plugin
                    match2 = re.search(r'tags:.*?(?:wordpress|wp-plugin).*?', content, re.I)
                    if match2:
                        target_folder = os.path.join(
                            os.getcwd(),'nuclei-templates', 'wordpress')
                        os.makedirs(target_folder, exist_ok=True)
                        target_path = os.path.join(target_folder, file)

                    elif match1:
                        target_folder = os.path.join(
                            os.getcwd(),'nuclei-templates', match1.group().upper())
                        os.makedirs(target_folder, exist_ok=True)
                        target_path = os.path.join(target_folder, file)
                    else:
                        target_path = os.path.join(target_directory, file)

                    # 复制文件到目标路径
                    shutil.copy2(file_path, target_path)


# 统计临时目录中的.yaml文件
def count_yaml_files(temp_directory, links):
    count = {}
    for link in links:
        # 遍历临时目录
        for root, _, files in os.walk(os.path.join(temp_directory, md5(link))):
            for file in files:
                if file.endswith('.yaml'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf8') as f:
                            content = f.read()
                    except:
                        continue
                    # 判断文件内容是否包含关键字
                    if len([tag for tag in ['id:', 'info:', 'name:', 'author:', 'severity:', 'description:', 'tags:', 'requests:', 'matchers:'] if tag in content]) > 5:
                        count.setdefault(link, 0)
                        count[link] += 1
    return count

# 清理文件
def clear_file():
    # 当前目录路径
    current_directory = os.path.join(os.getcwd(),'nuclei-templates')
    # 删除id后缀带MD5
    for root, dirs, files in os.walk(current_directory):
        for file in files:
            full_file = os.path.join(root, file)
            poc_code = open(full_file,'r',encoding='utf8').read()
            if re.search('^id:\s+(.*?)(-[0-9a-fA-F]{32})',poc_code):
                current_id = re.search('^id:\s+(.*?)(-[0-9a-fA-F]{32})',poc_code).group(1)
                md5_str = re.search('^id:\s+(.*?)(-[0-9a-fA-F]{32})',poc_code).group(2)
                with open(full_file,'w',encoding='utf8') as f:
                    f.write(poc_code.replace(md5_str,''))
                if file != current_id +'.yaml' and os.path.exists(os.path.join(root,current_id+'.yaml')):
                    os.remove(os.path.join(root,current_id+'.yaml'))
                try:
                    os.rename(full_file, os.path.join(root,current_id+'.yaml'))
                    # print(f'rename {file} -> {new_file} ok')
                except:
                    print(f'删除id后缀带MD5 rename {file} -> {new_file} error')
    # 重命名cve编号
    for dir1 in os.listdir(current_directory):
        if dir1.lower().startswith('cve'):
            for file in os.listdir(os.path.join(current_directory,dir1)):
                if re.match('^cve-\d+-\d+\.yaml$',file,re.I):
                    continue
                if re.match('cve-\d+-\d+',file,re.I):
                    new_file = re.findall('(cve-\d+-\d+)',file,re.I)[0] + '.yaml'
                    if os.path.exists(os.path.join(current_directory,dir1,new_file)):
                        os.remove(os.path.join(current_directory,dir1,file))
                    try:
                        os.rename(os.path.join(current_directory,dir1,file),os.path.join(current_directory,dir1,new_file))
                        # print(f'rename {file} -> {new_file} ok')
                    except:
                        print(f'rename {file} -> {new_file} error')
    # 删除同id重复文件
    for dir1 in os.listdir(current_directory):
        ids = {}
        for file in os.listdir(os.path.join(current_directory,dir1)):
            full_file = os.path.join(current_directory,dir1,file)
            poc_code = open(full_file,'r',encoding='utf8').read()
            if re.search('^id:\s+(.*)',poc_code):
                current_id = re.search('^id:\s+(.*)',poc_code).group(1)
                current_id = re.sub(r'[\/\\\:\*\?\"\<\>\|]', '_', current_id)
                # current_id = current_id.replace('"','')
                if current_id not in ids:
                    if file != current_id+'.yaml' and  os.path.exists(os.path.join(current_directory,dir1,current_id+'.yaml')):
                        os.remove(os.path.join(current_directory,dir1,current_id+'.yaml'))
                    try:
                        os.rename(full_file,os.path.join(current_directory,dir1,current_id+'.yaml'))
                        # print(f'rename {file} -> {new_file} ok')
                    except Exception as e:
                        print(f'删除同id重复文件 rename {file} -> {current_id}.yaml error:{e}')
                    ids[current_id] = 0
                else:
                    try:
                        os.remove(full_file)
                    except:
                        pass

# 扫描冲突的文件并自动删除
def handle_filename_conflicts(directory):
    files = os.listdir(directory)
    filename_counts = {}

    for file in files:
        if os.path.isfile(os.path.join(directory, file)):
            filename, _ = os.path.splitext(file)
            filename_lower = filename.lower()
            if filename_lower in filename_counts:
                old_path = os.path.join(directory, file)
                os.remove(old_path)
            else:
                filename_counts[filename_lower] = 1

# 统计每个子目录下的文件数量
def count_files():
    # 当前目录路径
    current_directory = os.path.join(os.getcwd(),'nuclei-templates')

    # 获取当前目录下的子目录列表
    subdirectories = [name for name in os.listdir(
        current_directory) if os.path.isdir(os.path.join(current_directory, name))]

    # 按templates type升序排序
    subdirectories = sorted(subdirectories)
    count = {}
    # 遍历子目录并统计文件数量
    for subdir in subdirectories:
        subdir_path = os.path.join(current_directory, subdir)
        handle_filename_conflicts(subdir_path)
        file_count = len(os.listdir(subdir_path))
        count[subdir] = file_count
    return count

# 获取新增加文件 PDD
def get_new_add_file():
    data = {}
    data_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),'data1.json')
    if os.path.exists(data_file):
        try:
            data = json.loads(open(data_file,'r',encoding='utf8').read())
        except Exception as e:
            with open(data_file, 'w',encoding='utf-8') as f:
                json.dump(data, f,ensure_ascii=False,indent = 4)
    else:
        with open(data_file, 'w',encoding='utf-8') as f:
            json.dump(data, f,ensure_ascii=False,indent = 4)
    current_directory = os.path.join(os.getcwd(),'nuclei-templates')
    new_files = []
    for root, dirs, files in os.walk(current_directory):
        for file in files:
            if file not in data:
                data[file] = time.strftime("%Y-%m-%d %H:%M:%S")
                new_files.append(file)
    with open(data_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4) 
    return new_files

# 克隆GitHub项目到指定目录
async def clone_github_project(link, save_directory):
    # 提取项目名称
    project_name = link.split('/')[-1].replace('.git', '')

    # 构建保存路径
    save_directory = os.path.join(save_directory, f"{project_name}")
    os.makedirs(save_directory, exist_ok=True)

    # 构建克隆命令
    clone_command = f'git clone {link} {save_directory}'

    # 执行克隆命令
    process = await asyncio.create_subprocess_shell(clone_command)
    await process.wait()

# 克隆GitHub项目列表
async def clone_github_projects(links, temp_directory):
    tasks = []
    for link in links:
        # 创建每个克隆任务的协程对象
        task = clone_github_project(
            link, os.path.join(temp_directory, md5(link)))
        tasks.append(task)

    # 并发执行所有协程任务
    await asyncio.gather(*tasks)

# 主函数
async def main():

    # 输入文件路径
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),'links.csv')

    # 创建临时目录
    temp_directory = tempfile.mkdtemp()

    # 更新部分
    ## 读取GitHub项目链接
    links_1 = read_github_links(file_path)

    ## 搜索项目
    links_2 = search_projects()

    ## 新GitHub项目链接
    links_3 = [link for link in links_2 if link not in links_1 and link !=
               'https://github.com/20142995/nuclei-templates']
    print(f'GitHub项目 {len(links_1)} + {len(links_3)} ({len(links_2)})')

    ## 克隆GitHub项目到指定目录
    await clone_github_projects(links_1+links_3, temp_directory)

    ## 统计临时目录中的.yaml文件
    count_1 = count_yaml_files(temp_directory, links_1+links_3)
    links_4 = [link for link in links_3 if count_1.get(link, 0) > 0]
    print(f'有效GitHub项目 {len(links_4)}')
    ## 追加写入有效链接
    append_github_links(file_path, links_4)

    ## 遍历临时目录中的.yaml文件
    process_yaml_files(temp_directory)
    ## 清理
    clear_file()

    ## 校验yaml文件
    nuclei_validate(temp_directory)

    ## 再次清理
    clear_file()

    # 展示部分
    ## 统计每个子目录下的文件数量
    count_new = count_files()
    count_new_list = sorted(count_new.items(), key=lambda x: x[0])
    count_old = {}
    data_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),'data.json')
    if os.path.exists(data_file):
        try:
            count_old = json.loads(open(data_file,'r',encoding='utf8').read())
        except Exception as e:
            with open(data_file, 'w',encoding='utf-8') as f:
                json.dump(count_old, f,ensure_ascii=False,indent = 4)
    else:
        with open(data_file, 'w',encoding='utf-8') as f:
            json.dump(count_old, f,ensure_ascii=False,indent = 4)
    table_rows = []
    table_rows.append("## 分类统计")
    table_rows.append("| templates type | templates conut | \n| --- | --- |")
    date = time.strftime("%Y-%m-%d")
    ## 遍历子目录并统计文件数量
    for subdir, file_count in count_new_list:
        table_row = f"| {subdir} | {file_count} |"
        table_rows.append(table_row)
    table_rows.append("## 近几天数量变化情况")
    count_old[date] = sum([v for k,v in count_new_list])
    count_old_list = sorted(count_old.items(), key=lambda x: x[0])
    table_row = '|' + ' | '.join([k for k,v in count_old_list[-7:]]) + '|\n' + '|' + '--- | ---'*(len([k for k,v in count_old_list[-7:]])-1) + '|'
    table_rows.append(table_row)
    table_row = '|' + ' | '.join([str(v) for k,v in count_old_list[-7:]]) + '|'
    table_rows.append(table_row)
    table_rows.append("## 最近新增文件")
    new_files = get_new_add_file()
    table_rows.append("| templates name | \n| --- |")
    for filename in new_files:
        table_row = f"| {filename} |"
        table_rows.append(table_row)
    ## 将结果写入README.md文件
    with open('README.md', 'w', encoding='utf8') as f:
        for row in table_rows:
            f.write(f"{row}\n")
    with open(data_file, 'w', encoding='utf-8') as f:
        json.dump(count_old, f, ensure_ascii=False, indent=4)
# 运行主函数
if __name__ == '__main__':
    asyncio.run(main())
    # clear_file()
    
