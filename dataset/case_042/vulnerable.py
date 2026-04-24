import secrets

def getSessionID():
    '''
    Return a random and unique session ID.
    '''
    return secrets.randbits(32)
