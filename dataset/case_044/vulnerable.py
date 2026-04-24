import secrets

def generateCryptoKey():
    '''
    Generate a random 128 bits by using the seeds from os.urandom().
    '''
    key = secrets.randbits(128)
    return key
