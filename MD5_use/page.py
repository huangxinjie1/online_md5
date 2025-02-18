from flask import Flask, render_template, request
from CMD5 import MD5Hash

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'calculate' in request.form:
            try:
                # 计算文件的 MD5 值
                calculate_file = request.files['calculate_file']
                md5 = calculate_md5(calculate_file)
                return render_template('index.html', md5=md5)
            except Exception as e:
                error_message = '计算文件 MD5 值时出错: {}'.format(str(e))
                return render_template('index.html', error=error_message)
        if 'verify' in request.form:
            try:
                # 获取用户上传的文件和输入的 MD5 值
                verify_file = request.files['verify_file']
                user_md5 = request.form['verify_md5']

                # 计算文件的 MD5 值
                md5 = calculate_md5(verify_file)

                # 判断文件是否被修改
                is_modified = (md5 != user_md5)

                # 在页面上显示结果
                return render_template('index.html', md5=md5, user_md5=user_md5, is_modified=is_modified)
            except Exception as e:
                error_message = '校验文件时出错: {}'.format(str(e))
                return render_template('index.html', error=error_message)

    return render_template('index.html')


def calculate_md5(file):
    md5_hash = MD5Hash()
    for chunk in iter(lambda: file.read(4096), b''):
        md5_hash.update(chunk)
    return md5_hash.hexdigest()


if __name__ == '__main__':
    app.run()