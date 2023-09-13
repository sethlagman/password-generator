"""A multifunctional password generator with encryption"""

from cryptography.fernet import Fernet
from pathlib import Path
import string
import json
import random
import base64

class PasswordGenerator():
    """Represents the class for password generator and its functionalities"""

    def __init__(self, name='', file_name=''):
        
        # Initialize a list of characters to be used for generating characters
        self.characters = list(string.ascii_letters) + list(string.digits)

        # Initialize an empty dictionary, used for storing user's info & passwords
        self.data = {}

        # Specifies the name associate with the file's data
        self.name = name

        # Specifies where to store the file
        self.file_name = file_name

        # Default length of password is 10
        self.length = 10

        # Initialize the attributes to None
        self.password = None
        self.file_password = None
        self.key = None

    def generate(self):
        """Creates a random generated password"""

        self.password = "".join(random.choices(self.characters, k=self.length))

    def pwd_length(self):
        """Changes the password's length"""

        while True:
            length = input("Enter the password's length: ")
            try:
                length = int(length)
                if 10 > length <= 30:
                    print("Minimum characters is 10!")
                elif 10 <= length > 30:
                    print("Maximum characters is 30!")
                else:
                    self.length = length
                    break
            except ValueError:
                print("Enter a number!")

    def encrypt(self):
        """Encrypts the password"""

        # Generate a random key for encryption
        self.key = Fernet.generate_key()

        # Create an encryption handler with the generated key
        encryption_handler = Fernet(self.key)

        # Encode as bytes
        self.password = self.password.encode('utf-8')
        self.file_password = self.file_password.encode('utf-8')

        # Encrypt the user's password and file password
        encrypted_password = encryption_handler.encrypt(self.password)
        encrypted_file_password = encryption_handler.encrypt(self.file_password)

        # Store the encrypted data in self.data (dictionary)
        self.data[self.name] = {
            "Key": [self.key],
            "File Password": encrypted_file_password,
            "Password": [encrypted_password],
        }

    def decrypt(self, data):
        """Decrypts the password"""

        # Initialize a dictionary to store the decrypted datas
        decrypted_data = {}

        # Check if input password == file password, if True then do this:
        if self.verify(data):

            # Deserializes first the file's data
            data = FileHandler().deserialize(data)

            for name, content in data.items():
                key_list = content['Key']
                file_pwd = content['File Password']
                pwd_list = content['Password']

                # Uses the first stored key for the decryption of file password
                data_key = base64.urlsafe_b64decode(key_list[0].encode('utf-8'))
                encryption_handler = Fernet(data_key)

                # Define the dictionary's structure
                decrypted_data[name] = {}
                decrypted_data[name]["Key"] = key_list
                decrypted_data[name]["File Password"] = encryption_handler.decrypt(file_pwd).decode('utf-8')
                decrypted_data[name]["Password"] = []

            # Decrypts each user's password with its own corresponding key
            for index, (key, password) in enumerate(zip(key_list, pwd_list)):
                data_key = base64.urlsafe_b64decode(key.encode('utf-8'))
                encryption_handler = Fernet(data_key)
                decrypted_data[name]["Password"].append(encryption_handler.decrypt(password).decode('utf-8'))

            # Display all the decrypted data
            print(f"Name: {name.title()}")
            print(f"File Password: {decrypted_data[name]['File Password']}")
            print(f"Stored Passwords: {', '.join(decrypted_data[name]['Password'])}")

            return decrypted_data
        
        # If False, then do this:
        else:
            print("Wrong file password!")

    def verify(self, data):
        """Verifies if the input passsword is equal to the current file password"""

        # Retrieve the input password from the class attribute (stored in the PasswordGenerator object)
        input_password = self.file_password

        for name, content in data.items():
            # Extract the encryption key from the data
            data_key = content['Key'][0]

            # Decode the data key from base64 encoding
            data_key = base64.urlsafe_b64decode(data_key)
            encryption_handler = Fernet(data_key)
        
        for name, content in data.items():
            # Decode the file's password then decrypt it using the data key
            file_password = base64.b64decode(content['File Password'])
            file_password = encryption_handler.decrypt(file_password).decode('utf-8')
            
        return input_password == file_password
        
    def filepwd(self):
        """Requests a password for the file"""

        self.file_password = input("Enter the file password: ")


class FileHandler:
    """Utility class for file operation"""

    def write(self, data, file_name):
        """Writes to the given file"""

        # Check if file/path already exists, if True do this:
        if Path(file_name).exists():
            print("File already exists!")

            while True:
                print("""Commands:
                    - 'overwrite': Overwrites the file
                    - 'add': Append the new password
                    - 'return': Go back""")
                command = input(">>> ").lower()
                existing_data = self.read(file_name)
                pwd_gen = PasswordGenerator()

                # Overwrites the existing data with the new data
                if command == 'overwrite':

                    pwd_gen.filepwd()
                    # Checks first if given password corresponds to the file's password
                    if pwd_gen.verify(existing_data):

                        # If True, overwrite the file
                        with open(file_name, 'w') as file_obj:
                            json.dump(data, file_obj, indent=2)
                            
                        print("Overwrote successfully!")
                        break

                    else:
                        print("Wrong file password!")

                # Adds the newly generated password and key to the existing file
                elif command == 'add':

                    pwd_gen.filepwd()
                    # Checks first if given password corresponds to the file's password
                    if pwd_gen.verify(existing_data):

                        # Retrieves the existing key list and password list
                        for name, content in existing_data.items():
                            pwd_list = content["Password"]
                            key_list = content["Key"]

                        # Adds the new key and password to the existing key list and password
                        for name, content in data.items():
                            pwd_list += content["Password"]
                            key_list += content["Key"]
                        
                        # Writes to the file with the updated data
                        with open(file_name, 'w') as file_obj:
                            json.dump(existing_data, file_obj, indent=2)

                        print("Added successfully!")
                        break

                    else:
                        print("Wrong file password!")
                
                elif command == 'return':
                    break

                else:
                    print("Invalid input!")

        # If False, just write to the given path/file
        else:
            with open(file_name, 'w') as file_obj:
                json.dump(data, file_obj, indent=2)
            print("Created successfully!")

    def read(self, file_name):
        """Reads the file"""

        with open(file_name, 'r') as file_obj:
            data = json.load(file_obj)
            return data
        
    def serialize(self, data):
        """Serializes data"""

        for name, content in data.items():
            for label, value in content.items():
                
                # If value is not a list, encode each value to b64 format
                if type(value) != list:
                    content[label] = base64.b64encode(value).decode('utf-8')

                # If value is a list, loop through, and encode each item to b64 format
                elif type(value) == list:
                    for index, item in enumerate(value):
                        value[index] = base64.b64encode(item).decode('utf-8')

    def deserialize(self, data):
        """Deserializes data"""

        for name, content in data.items():
            for label, value in content.items():

                # Decodes all the stored keys
                if label == 'Key':
                    for key in value:
                        key = base64.urlsafe_b64decode(key)

                # If value is not a list, decode each value
                elif type(value) != list:
                    content[label] = base64.urlsafe_b64decode(value)
                
                # If value is not a list, loop through, and decode each item
                elif type(value) == list:
                    for index, item in enumerate(value):
                        value[index] = base64.urlsafe_b64decode(item)
        return data


def main():
    
    while True:
        print("""Commands:
            - 'create': Generate and store password
            - 'read': Retrieve the passwords
            - 'quit': Exits the program""")
        command = input(">>> ").lower()
        
        if command == 'create':
            name = input("Enter your name: ")
            if not name:
                print("Enter a name!")
                break

            file_name = input("Enter the file name you want to store your passwords in: ")
            if not file_name:
                print("Enter a file name!")
                break
            
            # Create a pwdgenerator object, requests pwd length, requests a pwd for the file, generate pwd, then encrypt
            pwdgen = PasswordGenerator(name, file_name)
            pwdgen.pwd_length()
            pwdgen.filepwd()
            pwdgen.generate()
            pwdgen.encrypt()

            # Serialize and write the data to a file/path
            FileHandler().serialize(pwdgen.data)
            FileHandler().write(pwdgen.data, file_name)

        elif command == 'read':
            try:
                file_name = input("Enter the file name you want to retrieve: ")
                existing_data = FileHandler().read(file_name)
            except FileNotFoundError:
                print("File not found!")
            else:
                # Create a pwdgenerator object, asks for the file's pwd, then decrypt
                pwdgen = PasswordGenerator()
                pwdgen.filepwd()
                pwdgen.decrypt(existing_data)

        elif command == 'quit':
            break

        else:
            print("Invalid input!")

if __name__ == '__main__':
    main()
