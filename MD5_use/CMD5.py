import ctypes
import hashlib
import os
import time

import pymysql
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# 加载 MD5 库
md5_lib = ctypes.CDLL('./md5.dll')


# 定义 MD5_CTX 结构体
class MD5_CTX(ctypes.Structure):
    _fields_ = [
        ('state', ctypes.c_uint32 * 4),
        ('count', ctypes.c_uint32 * 2),
        ('buffer', ctypes.c_ubyte * 64)
    ]


# 定义 MD5_Init 函数接口
md5_init = md5_lib.MD5_Init
md5_init.argtypes = [ctypes.POINTER(MD5_CTX)]
md5_init.restype = None

# 定义 MD5_Update 函数接口
md5_update = md5_lib.MD5_Update
md5_update.argtypes = [ctypes.POINTER(MD5_CTX), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32]
md5_update.restype = None

# 定义 MD5_Final 函数接口
md5_final = md5_lib.MD5_Final
md5_final.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(MD5_CTX)]
md5_final.restype = None


# 封装成类，方便调用
class MD5Hash:
    # 构造函数
    def __init__(self, key="MyEncryptionKey"):
        """
        初始化MD5Hash对象
        :param key: 加密密钥，默认为"MyEncryptionKey" : str
        """
        self.ctx = MD5_CTX()
        md5_init(ctypes.byref(self.ctx))

        # 建立与MySQL数据库的连接
        self.cnx = pymysql.connect(host='124.220.177.102', user='jie', password='Ujs3200604053', database='Package')
        self.cursor = self.cnx.cursor()

        self.key = key.encode().ljust(32, b'\0')[:32]

    # 析构函数
    def __del__(self):
        """
        对象销毁时的清理操作，关闭数据库连接和游标
        :return:None
        """
        # 关闭游标和数据库连接
        self.cursor.close()
        self.cnx.close()

    def encrypt(self, plaintext: str) -> str:
        """
        加密给定的明文字符串
        :param plaintext: 明文字符串: str
        :return: 密文字符串，以16进制表示 ->str
        """
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return iv.hex() + ciphertext.hex()

    def decrypt(self, ciphertext: str) -> str:
        """
        解密给定的密文字符串
        :param ciphertext:  密文字符串，以16进制表示: hex_str
        :return: 解密后的明文字符串 -> str
        """
        try:
            iv = bytes.fromhex(ciphertext[:AES.block_size * 2])
            ciphertext = bytes.fromhex(ciphertext[AES.block_size * 2:])
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted_text.decode()
        except (ValueError, KeyError, TypeError):
            return ""

    def update(self, data: bytes):
        """
        更新MD5哈希值的上下文
        :param data: 要更新的数据，以字节形式传入 : bytes
        :return: None
        """
        md5_update(ctypes.byref(self.ctx), ctypes.cast(data, ctypes.POINTER(ctypes.c_ubyte)), len(data))

    def digest(self) -> bytes:
        """
        计算MD5哈希值的摘要
        :return: MD5哈希值的摘要，以字节形式表示 -> bytes
        """
        digest = (ctypes.c_ubyte * 16)()
        md5_final(digest, ctypes.byref(self.ctx))
        return bytes(digest)

    def hexdigest(self) -> str:
        """
        计算MD5哈希值的十六进制表示形式
        :return: MD5哈希值的十六进制表示形式字符串 -> str
        """
        return self.digest().hex()

    def string_hexdigest(self, data: str) -> str:
        """
        计算字符串的MD5摘要
        :param data: 输入的字符串 : str
        :return: 字符串的MD5哈希值的十六进制表示形式字符串 -> str
        """
        # 重置MD5_CTX的状态
        md5_init(ctypes.byref(self.ctx))
        self.update(data.encode())
        return self.hexdigest()

    def file_hexdigest(self, file_path: str) -> str:
        """
        计算文件的MD5哈希值的十六进制表示形式
        :param file_path: 文件路径 : str
        :return: 文件的MD5哈希值的十六进制表示形式字符串 -> str
        """
        # 重置MD5_CTX的状态
        md5_init(ctypes.byref(self.ctx))

        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b''):
                self.update(chunk)
        return self.hexdigest()

    def load_hash_file(self, hash_file: str) -> dict:
        """
        从哈希文件加载文件名和哈希值的字典
        :param hash_file: 哈希文件的路径 : str
        :return: 文件名和哈希值组成的字典 -> dict
        """
        file_hash_dict = {}
        if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
            with open(hash_file, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:
                        values = line.split('\t')
                        if len(values) == 2:
                            file_name, file_hash = values
                            file_hash_dict[file_name] = file_hash
                        else:
                            print(f"忽略格式错误的行: {line}")
        return file_hash_dict

    def insert_md5_to_sql(self, file_name: str, file_hash: str):
        """
        将文件名和哈希值插入到数据库中
        :param file_name: 文件名 : str
        :param file_hash: 哈希值 : str
        :return:
        """
        # 查询数据库中的所有数据
        select_query = "SELECT file_name, md5_hash FROM file_md5"
        self.cursor.execute(select_query)
        results = self.cursor.fetchall()

        # 解密后并比较文件名去重
        for result in results:
            db_file_name = self.decrypt(result[0])
            if db_file_name == file_name:
                # 删除重复数据
                delete_query = "DELETE FROM file_md5 WHERE file_name = %s OR md5_hash = %s"
                data = (result[0], result[1])
                self.cursor.execute(delete_query, data)
                self.cnx.commit()
                break

        # 插入数据
        encrypted_file_name = self.encrypt(file_name)
        encrypted_file_hash = self.encrypt(file_hash)
        insert_query = "INSERT INTO file_md5 (file_name, md5_hash) VALUES (%s, %s)"
        data = (encrypted_file_name, encrypted_file_hash)
        self.cursor.execute(insert_query, data)
        self.cnx.commit()

    def compare_hash_with_database(self, hash_file: str, filename: str) -> bool:
        """
        将文件的哈希值与数据库中的哈希值进行比较
        :param hash_file: 存放哈希值的文件路径 : str
        :param filename: 要比较哈希值的文件名 : str
        :return: 比较结果的布尔值，True表示哈希值一致，False表示哈希值不一致或文件名不存在 -> bool
        """
        # 从数据库中获取文件名和哈希值
        select_query = "SELECT file_name, md5_hash FROM file_md5"
        self.cursor.execute(select_query)
        results = self.cursor.fetchall()
        db_hash = None
        for result in results:
            if self.decrypt(result[0]) == filename:
                db_hash = self.decrypt(result[1])

        # 从本地hash_file中获取文件的哈希值
        local_hash = None
        with open(hash_file, 'r') as file:
            for line in file:
                file_name, file_hash = line.strip().split('\t')
                if self.decrypt(file_name) == filename:
                    local_hash = self.decrypt(file_hash)
                    break

        # 比较本地哈希值和数据库哈希值
        if local_hash is None:
            print(f"本地无法找到‘{filename}’的哈希值,可能已经被破坏！")
            return False

        if db_hash is None:
            print(f"数据库无法找到文件 '{filename}' 的哈希值,可能已经被破坏!")
            return False

        if local_hash == db_hash:
            print(f"文件 '{filename}' 的哈希值与数据库一致！")
            return True
        else:
            print(f"文件 '{filename}' 的哈希值与数据库不一致！")
            return False

    def save_md5_to_hash_file(self, hash_file: str, file_paths: list):
        """
        将文件的哈希值保存到存放哈希值的文件中
        :param hash_file: 哈希文件的路径 : str
        :param file_paths: 文件路径列表 :str
        :return:None
        """
        # 加载已存在的加密文件名和哈希值
        existing_hash_dict = self.load_hash_file(hash_file)

        # 解密已存在的文件名和哈希值，并将其存入字典
        decrypted_hash_dict = {}
        for encrypted_file_name, encrypted_file_hash in existing_hash_dict.items():
            decrypted_file_name = self.decrypt(encrypted_file_name)
            decrypted_file_hash = self.decrypt(encrypted_file_hash)
            decrypted_hash_dict[decrypted_file_name] = decrypted_file_hash

        # 处理新的文件
        with open(hash_file, 'w') as file:
            for file_path in file_paths:
                file_name = os.path.basename(file_path)
                file_hash = self.file_hexdigest(file_path)

                # 去重
                if decrypted_hash_dict.get(file_name) != file_hash:
                    decrypted_hash_dict[file_name] = file_hash
            # 存储到数据库和文件
            for decrypted_file_name, decrypted_file_hash in decrypted_hash_dict.items():
                self.insert_md5_to_sql(decrypted_file_name, decrypted_file_hash)
                encrypted_file_name = self.encrypt(decrypted_file_name)
                encrypted_file_hash = self.encrypt(decrypted_file_hash)
                file.write(f"{encrypted_file_name}\t{encrypted_file_hash}\n")

    def verify_file_integrity(self, hash_file: str, file_path: str) -> bool:
        """
         验证文件的完整性
        :param hash_file:  哈希文件的路径 : str
        :param file_path: 文件路径 : str
        :return: 验证结果的布尔值，True表示文件完整性验证通过，False表示文件完整性验证失败 -> bool
        """
        file_hash_dict = self.load_hash_file(hash_file)
        file_name = os.path.basename(file_path)
        sync = self.compare_hash_with_database(hash_file, file_name)
        if not sync:
            print("存储哈希值文件被更改无法完成校验，请手动输出hash值完成校验！")
            return False
        expected_md5 = None
        for encrypt_file_name, encrypt_file_hash in file_hash_dict.items():
            if self.decrypt(encrypt_file_name) == file_name:
                expected_md5 = self.decrypt(encrypt_file_hash)
        if expected_md5 is None:
            print("无法找到文件的哈希值")
            return False
        actual_md5 = self.file_hexdigest(file_path)
        if actual_md5 == expected_md5:
            return True
        else:
            return False

    def verify_file_integrity_md5(self, file_path: str, expected_md5: str) -> bool:
        """
        通过输入文件的期望md5值验证文件完整性
        :param file_path: 文件路径 : str
        :param expected_md5: 16进制的哈希值字符串 : str
        :return: 验证结果的布尔值，True表示文件完整性验证通过，False表示文件完整性验证失败 -> bool
        """
        actual_md5 = self.file_hexdigest(file_path)
        if actual_md5 == expected_md5:
            return True
        else:
            return False

    def close_connection(self):
        # 显示游标和数据库连接
        self.cursor.close()
        self.cnx.close()


if __name__ == "__main__":
    # # 字符串摘要计算
    data = "Hello, World!"
    # md5_hash = MD5Hash()
    #
    # # 使用 MD5Hash 类计算摘要
    # start_time = time.time()
    # md5_digest = md5_hash.string_hexdigest(data)
    # end_time = time.time()
    #
    # print("自定义 MD5 摘要耗时:", end_time - start_time, "秒")
    # print('MD5 摘要 (自定义):', md5_digest)
    #
    # # 使用 hashlib 库计算摘要
    # hashlib_md5 = hashlib.md5()
    # start_time = time.time()
    # hashlib_md5.update(data.encode())
    # hashlib_digest = hashlib_md5.hexdigest()
    # end_time = time.time()
    #
    # print('MD5 摘要 (hashlib):', hashlib_digest)
    # print("hashlib MD5 摘要耗时:", end_time - start_time, "秒")
    #
    # # 比较两种方法得到的摘要是否相同
    # if md5_digest == hashlib_digest:
    #     print('MD5 摘要匹配')
    # else:
    #     print('MD5 摘要不匹配')
    #
    # # 文件摘要计算
    # file_path = '信息论：基础理论与应用 第4版.pdf'
    # md5_hash = MD5Hash()
    #
    # # 使用 MD5Hash 类计算文件摘要
    # start_time = time.time()
    # md5_digest = md5_hash.file_hexdigest(file_path)
    # end_time = time.time()
    #
    # print("自定义 MD5 摘要耗时:", end_time - start_time, "秒")
    # print('MD5 摘要 (自定义):', md5_digest)
    #
    # # 使用 hashlib 库计算文件摘要
    # hashlib_md5 = hashlib.md5()
    # start_time = time.time()
    # with open(file_path, 'rb') as file:
    #     while True:
    #         data = file.read(4096)
    #         if not data:
    #             break
    #         hashlib_md5.update(data)
    # hashlib_digest = hashlib_md5.hexdigest()
    # end_time = time.time()
    #
    # print('MD5 摘要 (hashlib):', hashlib_digest)
    # print("hashlib MD5 摘要耗时:", end_time - start_time, "秒")
    #
    # # 比较两种方法得到的摘要是否相同
    # if md5_digest == hashlib_digest:
    #     print('MD5 摘要匹配')
    # else:
    #     print('MD5 摘要不匹配')

    # 验证文件完整性,首先生成摘要保存进文件和数据库
    # 存储哈希文件的路径
    # hash_file = 'hash_file.txt'
    # md5_save = MD5Hash()
    # # 计算哈希值的文件路径列表
    # file_paths = ['example.txt', '信息论：基础理论与应用 第4版.pdf']
    # # 追加写入文件名和哈希值到哈希文件
    # md5_save.save_md5_to_hash_file(hash_file, file_paths)

    # 验证example.txt是否被修改
    # md5_viri = MD5Hash()
    # file_path = 'example.txt'
    # result = md5_viri.verify_file_integrity(hash_file, file_path)
    # if result:
    #     print("文件完整性验证通过")
    # else:
    #     print("文件完整性验证失败")

    # # 通过自己记录hash值验证文件完整性
    # md5_viri2 = MD5Hash()
    # file_path2 = "信息论：基础理论与应用 第4版.pdf"
    # hash_record = "9ab68b7af09c81f201e62b04fc7eaa23"
    # result2 = md5_viri2.verify_file_integrity_md5(file_path2, hash_record)
    # if result2:
    #     print("文件完整性验证通过")
    # else:
    #     print("文件完整性验证失败")