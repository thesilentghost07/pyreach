from service import process_user_upload

def main():
    sample_yaml = "user: admin\nrole: superuser"
    result = process_user_upload(sample_yaml)
    return result

if __name__ == "__main__":
    main()
