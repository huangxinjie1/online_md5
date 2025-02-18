from CMD5 import MD5Hash


def main():
    md5 = MD5Hash()  # 创建 MD5Hash 对象
    while True:
        choice = input("\n\n#######MD5文件校验工具#######\n请输入操作:0.退出\n1.帮助\n2.生成字符串 MD5 摘要\n3.生成文件MD5摘要\n4.生成文件摘要并保存\n5.通过本地保存的MD5值校验文件\n6.通过期望的MD5进行文件校验\n")

        if choice == '0':
            break

        elif choice == '1':
            print("帮助：")
            print("0.退出：退出程序")
            print("1.帮助：显示帮助信息")
            print("2.生成字符串 MD5 摘要：生成给定字符串的 MD5 摘要,需要输入一个字符串")
            print("3.生成文件 MD5 摘要：生成给定文件的 MD5 摘要,需要输入一个文件的路径")
            print("4.生成文件摘要并保存：生成给定文件的 MD5 摘要并保存到哈希文件中,输入文件的路径(可以多个,以空格分割)和保存hash值的文件路径")
            print("5.通过本地保存的 MD5 值校验文件：通过本地保存的 MD5 值校验给定文件的完整性,输入要校验的文件路径和保存hash值的文件路径")
            print("6.通过期望的 MD5 进行文件校验：通过输入的期望 MD5 值校验给定文件的完整性,输入文件路径和hash值")

        elif choice == '2':
            plaintext = input("请输入要生成 MD5 摘要的字符串：")
            md5_digest = md5.string_hexdigest(plaintext)
            print(f"生成的 MD5 摘要为：{md5_digest}")

        elif choice == '3':
            file_path = input("请输入要生成 MD5 摘要的文件路径：")
            md5_digest = md5.file_hexdigest(file_path)
            print(f"生成的 MD5 摘要为：{md5_digest}")

        elif choice == '4':
            file_path = input("请输入要生成 MD5 摘要并保存的文件路径：").split()
            print(file_path)
            hash_file = input("请输入要保存 MD5 摘要的哈希文件路径：")
            md5.save_md5_to_hash_file(hash_file, file_path)
            print("MD5 摘要已生成并保存到哈希文件中")

        elif choice == '5':
            hash_file = input("请输入保存 MD5 值的哈希文件路径：")
            file_path = input("请输入要校验的文件路径：")
            print(file_path)
            if md5.verify_file_integrity(hash_file, file_path):
                print("文件完整性校验通过")
            else:
                print("文件完整性校验失败")

        elif choice == '6':
            file_path = input("请输入要校验的文件路径：")
            expected_md5 = input("请输入期望的 MD5 值：")
            if md5.verify_file_integrity_md5(file_path, expected_md5):
                print("文件完整性校验通过")
            else:
                print("文件完整性校验失败")

        else:
            print("无效的选择，请重新输入操作编号。")


if __name__ == '__main__':
    main()