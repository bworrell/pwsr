__author__ = 'bworrell'

import hashlib
import struct
import hmac
from hmac import HMAC
from StringIO import StringIO
from mcrypt import MCRYPT

BLOCK_SIZE = 16 # 16 Byte blocks for Twofish
MODE_CBC = 'cbc'
MODE_ECB = 'ecb'

TYPE_END = 0xff

class PasswordError(Exception):
    pass

class PwSafeV3Field(object):
    HEADER_SIZE = 5 # 4 Bytes (data length) + 1 byte (field type)

    def __init__(self):
        self.data_length = 0 # length of the field data
        self.raw_length = 0 # length of the field itself, including field header
        self.num_blocks = 0 # number of cipher blocks required for field
        self.type_ = 0 # field type
        self.raw_value = None # field value including padding
        self.value = None # field value without padding
        self.padding = None # field value padding if present

    @classmethod
    def parse(cls, data, offset=0):
        obj = cls()

        if not hasattr(data, "read"):
            dataio = StringIO(data[offset:])
        else:
            data.seek(offset)
            dataio = data

        obj.data_length = struct.unpack('<l', dataio.read(4))[0]
        field_length = obj.data_length + 5 # 4 bytes (data length) + 1 byte (field type) + N bytes (data)

        if (field_length) > BLOCK_SIZE:
            obj.num_blocks = field_length / BLOCK_SIZE + (1 if field_length % BLOCK_SIZE else 0)
        else:
            obj.num_blocks = 1

        obj.type_ = ord(dataio.read(1))
        obj.raw_length = BLOCK_SIZE * obj.num_blocks
        obj.raw_value = dataio.read(obj.raw_length)
        obj.value = obj.raw_value[:obj.data_length]
        obj.padding = obj.raw_value[obj.data_length:]

        return obj

    def serialize(self):
        '''Writes out a field with the following format:

        LENGTH : 4 byte LE integer
        TYPE: 1 byte
        VALUE: n * BLOCK_SIZE string

        '''
        fmt= "<lB%ss" % (self.num_blocks * BLOCK_SIZE)
        data = struct.pack(fmt, (self.length, self.type_, (self.value + self.padding)))
        return data

    def __eq__(self, other):
        if self is other:
            return True

        if isinstance(other, basestring):
            return self.value == other
        elif isinstance(other, PwSafeV3Field):
            return self.value == other.value
        else:
            return False

    def __repr__(self):
        return  str(self.__dict__)

    def __str__(self):
        return self.value

    def __len__(self):
        length = PwSafeV3Field.HEADER_SIZE + len(self.value)

        if length < BLOCK_SIZE:
            return BLOCK_SIZE

        q = length / BLOCK_SIZE
        r = length % BLOCK_SIZE
        if r: q += 1

        return (BLOCK_SIZE * q)



class PWSafeV3Header(object):
    '''
                                                      Currently
    Name                        Value        Type    Implemented      Comments
    --------------------------------------------------------------------------
    Version                     0x00        2 bytes       Y              [1]
    UUID                        0x01        UUID          Y              [2]
    Non-default preferences     0x02        Text          Y              [3]
    Tree Display Status         0x03        Text          Y              [4]
    Timestamp of last save      0x04        time_t        Y              [5]
    Who performed last save     0x05        Text          Y   [DEPRECATED 6]
    What performed last save    0x06        Text          Y              [7]
    Last saved by user          0x07        Text          Y              [8]
    Last saved on host          0x08        Text          Y              [9]
    Database Name               0x09        Text          Y              [10]
    Database Description        0x0a        Text          Y              [11]
    Database Filters            0x0b        Text          Y              [12]
    Reserved                    0x0c        -                            [13]
    Reserved                    0x0d        -                            [13]
    Reserved                    0x0e        -                            [13]
    Recently Used Entries       0x0f        Text                         [14]
    Named Password Policies     0x10        Text                         [15]
    Empty Groups                0x11        Text                         [16]
    Reserved                    0x12        Text                         [13]
    End of Entry                0xff        [empty]       Y              [17]

    '''

    def __init__(self):
        self.fields = {}

    @classmethod
    def parse(cls, data, offset=0):
        obj = cls()
        type_ = None

        while type_ != TYPE_END:
            field = PwSafeV3Field.parse(data, offset)
            type_ = field.type_
            obj[type_] = field
            offset += len(field)

        return obj

    def __setitem__(self, key, value):
        self.fields[key] = value

    def __getitem__(self, item):
        return self.fields.get(item)

    def __len__(self):
        return sum(f.raw_length for f in self.fields.itervalues())

    def __str__(self):
        s = ""
        for k, v in self.fields.iteritems():
            s += "%s: %s\n" % (k, str(v))
        return s

class PWSafeV3Record(object):
    '''
    UUID                        0x01        UUID          Y              [1]
    Group                       0x02        Text          Y              [2]
    Title                       0x03        Text          Y
    Username                    0x04        Text          Y
    Notes                       0x05        Text          Y
    Password                    0x06        Text          Y              [3,4]
    Creation Time               0x07        time_t        Y              [5]
    Password Modification Time  0x08        time_t        Y              [5]
    Last Access Time            0x09        time_t        Y              [5,6]
    Password Expiry Time        0x0a        time_t        Y              [5,7]
    *RESERVED*                  0x0b        4 bytes       -              [8]
    Last Modification Time      0x0c        time_t        Y              [5,9]
    URL                         0x0d        Text          Y              [10]
    Autotype                    0x0e        Text          Y              [11]
    Password History            0x0f        Text          Y              [12]
    Password Policy             0x10        Text          Y              [13]
    Password Expiry Interval    0x11        2 bytes       Y              [14]
    Run Command                 0x12        Text          Y
    Double-Click Action         0x13        2 bytes       Y              [15]
    EMail address               0x14        Text          Y              [16]
    Protected Entry             0x15        1 byte        Y              [17]
    Own symbols for password    0x16        Text          Y              [18]
    Shift Double-Click Action   0x17        2 bytes       Y              [15]
    Password Policy Name        0x18        Text          Y              [19]
    End of Entry
    '''
    TYPE_TITLE      = 0x03
    TYPE_USERNAME   = 0x04
    TYPE_PASSWORD   = 0x06

    def __init__(self):
        self.title = None
        self.username = None
        self.password = None

        # used for type lookups and __len__ calculations
        self.fields = {}

    @classmethod
    def parse(cls, data, offset=0):
        obj = cls()
        type_ = None

        while type_ != TYPE_END:
            field = PwSafeV3Field.parse(data, offset)

            if field.type_ == cls.TYPE_TITLE:
                obj.title = field
            elif field.type_ == cls.TYPE_USERNAME:
                obj.username = field
            elif field.type_ == cls.TYPE_PASSWORD:
                obj.password = field

            obj[field.type_] = field
            offset += field.raw_length
            type_ = field.type_

        return obj

    def __setitem__(self, key, value):
        self.fields[key] = value

    def __getitem__(self, item):
        return self.fields.get(item)

    def __len__(self):
        return sum(f.raw_length for f in self.fields.itervalues())

    def __repr__(self):
        return str(self.__dict__)

    def __str__(self):
        return "[%s] u: %s p: %s" % (self.title, self.username, self.password)

class PWSafeV3PreHeader(object):
    def __init__(self):
        self.tag = None
        self.salt = None
        self.iter = None
        self.hpp = None
        self.b1 = None
        self.b2 = None
        self.b3 = None
        self.b4 = None
        self.iv = None

    @classmethod
    def parse(cls, data):
        obj = cls()

        if not hasattr(data, "read"):
            dataio = StringIO(data)
        else:
            data.seek(0)
            dataio = data

        obj.tag = dataio.read(4)
        obj.salt = dataio.read(32)
        obj.iter_ = struct.unpack("<l", dataio.read(4))[0]
        obj.hpp = dataio.read(32)
        obj.b1 = dataio.read(16)
        obj.b2 = dataio.read(16)
        obj.b3 = dataio.read(16)
        obj.b4 = dataio.read(16)
        obj.iv = dataio.read(16)

        return obj

    def __len__(self):
        return  (4+32+4+32+(16*4)+16)

    def __str__(self):
        return str(self.__dict__)

class PWSafeDB(object):
    EOF_MARKER =  "PWS3-EOFPWS3-EOF"
    HDR_OFFSET = 152

    def __init__(self):
        self.preheader = None # unencrypted area
        self.header = None
        self.records = []
        self.hmac = None

        self.pp = None # P'
        self.k = None
        self.l = None

    def _check_password(self, pp, db_hpp):
        hpp = hashlib.new("sha256")
        hpp.update(pp)
        hpp = hpp.digest()

        return db_hpp == hpp

    def _stretch_key(self, key, salt, iter_):
        h = hashlib.new("sha256")
        h.update(key)
        h.update(salt)
        digest = h.digest()

        for _ in xrange(iter_):
            tmp_h = hashlib.new("sha256")
            tmp_h.update(digest)
            digest = tmp_h.digest()

        return digest

    def _decrypt(self, data, key, iv=None, mode=MODE_ECB):
        twofish = MCRYPT('twofish', mode)
        twofish.init(key, iv)
        plaintext = twofish.decrypt(data)
        return plaintext

    def _decrypt_data_section(self, data, iv, k):
        ieof = data.rindex(PWSafeDB.EOF_MARKER)
        ciphertext = data[PWSafeDB.HDR_OFFSET:ieof]
        data_section = self._decrypt(ciphertext, k, iv, mode=MODE_CBC) # CBC required for
                                                                 #  decryption
        return data_section

    def parse(self, db, key):
        '''Parses a PWSafe v3 database file.'''
        try:
            data = db.read()
        except AttributeError:
            data = db

        preheader = PWSafeV3PreHeader.parse(data)

        pp = self._stretch_key(key, preheader.salt, preheader.iter_)
        if not self. _check_password(pp, preheader.hpp):
            raise PasswordError("Incorrect password")

        k = self._decrypt(preheader.b1, pp) + self._decrypt(preheader.b2, pp) # decrypt data
        l = self._decrypt(preheader.b3, pp) + self._decrypt(preheader.b4, pp) # used for hmac

        udata = self._decrypt_data_section(data, preheader.iv, k) # decrypted data section
        header = PWSafeV3Header.parse(udata)
        offset = len(header)

        records = []
        while offset < len(udata):
            record = PWSafeV3Record.parse(udata, offset)
            records.append(record)
            offset += len(record)

        self.preheader = preheader
        self.header = header
        self.records = records
        #self.hmac = hmac_
        self.pp = pp
        self.k = k
        self.l = l

    def __getitem__(self, item):
        # first we'll try to find the exact record
        for record in self.records:
            if record.title == item:
                return record

        results = self.search(item)
        if results:
            return results[0]

        return None

    def __iter__(self):
        for record in self.records:
            yield record.title


    def search(self, key):
        records = []
        for record in self.records:
            if key.lower() in record.title.value.lower():
                records.append(record)
        return records


    def __str__(self):
        s = ""
        s += str(self.preheader) + "\n"
        s += str(self.header) + "\n"
        for record in self.records:
            s += str(record) + "\n"
        return s
