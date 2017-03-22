import base64
import boto3
from Crypto.Cipher import AES

pad = lambda s: s + (32 - len(s) % 32) * ' '


def get_arn(aws_data):
    """
    :param aws_data: See encrypt_data below
    :return: AWS KMS customer master key ARN
    """
    return 'arn:aws:kms:{region}:{account_number}:key/{key_id}'.format(**aws_data)


def encrypt_data(aws_data, plaintext_message, encrypted_data_output_file, encrypted_data_key_output_file):
    """
    :param aws_data: a json dict of AWS data. E.g.:
    {
        'region': region,
        'account_number': aws_account_number,
        'key_id': master_key_id,
    }
    :param plaintext_message: The secret text to encrypt
    :param encrypted_data_output_file: The file location of where to write the encrypted data to
    :param encrypted_data_key_output_file: The file location of where to write the encrypted data key to
    :return: Nothing. This function is just used to write things to disk locations that you passed in

    usage:
     > from envelope_encryption_kms_boto_pycrypto import encrypt_data
     > aws_data = {'region': 'eu-west-1', 'account_number': '822381380577', 'key_id': '1496fea5-2125-4e0e-9592-96e327996fe2',}
     > encrypt_data(aws_data, "this is my secret", "/tmp/encrypted_data", "/tmp/encrypted_data_key")

     If you have some weird characters in your password string (like quotes)
     then use triple quotes around "this is my secret"
    """
    conn = boto3.client('kms')
    arn = get_arn(aws_data)

    data_key = conn.generate_data_key(KeyId=arn, KeySpec='AES_256')
    encrypted_data_key = data_key.get('CiphertextBlob')
    plaintext_data_key = data_key.get('Plaintext')

    crypter = AES.new(plaintext_data_key)
    encrypted_data = base64.b64encode(crypter.encrypt(pad(plaintext_message)))

    # Write encrypted data and key to disk
    # To Do: use try except things here?
    encrypted_data_file = open(encrypted_data_output_file, 'w')
    encrypted_data_file.write(encrypted_data)
    encrypted_data_file.close()

    encrypted_data_key_file = open(encrypted_data_key_output_file, 'w')
    encrypted_data_key_file.write(encrypted_data_key)
    encrypted_data_key_file.close()


def decrypt_data(encrypted_data_file, encrypted_data_key_file):
    """
    :param encrypted_data_file: File containing encrypted secret text
    :param encrypted_data_key_file: File containing the encrypted data key
    :return: The decrypted data from the encrypted_data_file

    Usage:
     > from envelope_encryption_kms_boto_pycrypto import decrypt_data
     > secret = decrypt_data("/tmp/encrypted_data", "/tmp/encrypted_data_key")
    """
    # Read the key from file:
    encrypted_data_key_file = open(encrypted_data_key_file, 'r')
    encrypted_data_key = encrypted_data_key_file.read()
    encrypted_data_key_file.close()

    # Decrypt the key via KMS:
    kms = boto3.client('kms')
    decrypted_key = kms.decrypt(CiphertextBlob=encrypted_data_key).get('Plaintext')
    crypter = AES.new(decrypted_key)

    # Read the encrypted data from file:
    encrypted_data_file = open(encrypted_data_file, 'r')
    encrypted_data = encrypted_data_file.read()
    encrypted_data_file.close()

    # Decrypt the data using the key and return the secret:
    return crypter.decrypt(base64.b64decode(encrypted_data)).rstrip()
