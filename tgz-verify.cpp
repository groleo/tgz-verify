#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>


#include <axTLS/crypto.h>
#include <axTLS/crypto_misc.h>


class Goopa
{
private:
    off_t _sig_off;
    off_t _sizeof_sig;
    off_t _sizeof_dgst;
    off_t _sizeof_pkcs_mark;
    off_t _sizeof_dgst_mark;
    const char* _tgz_name;
    const char* _tgz_basename;
    const char* _key_name;
private:
    int _fd=-1;
    uint8_t* _sig=0;
    uint8_t* _dgstD=0;
    uint8_t* _dgstC=0;
    const off_t _sizeof_pkcs_modulo = 256;

public:
    Goopa()
    {
        clean();
    }
    ~Goopa()
    {
        clean();
    }
    bool Verify(const char* t, const char* k)
    {
        if ( ! init(t,k)            ||
             ! extractSignature()   ||
             ! decryptDigest()      ||
             ! computeDigest()      ||
             ! compareDigests()
             )
        {
            clean();
            return false;
        }

        return true;
    }
private:
    bool init(const char* t, const char* k)
    {
        if (t==0 || k==0)
            return false;

        clean();
        _tgz_name=t;
        _tgz_basename=basename(t);
        _key_name=k;

        assert(_tgz_name!=0);

        _fd = open(_tgz_name, O_RDONLY);
        if (_fd==-1)
        {
            perror("Failed to open input file");
            return false;
        }

        _sig_off = (off_t)-1;

        _sizeof_pkcs_mark = strlen("PKCSSIG()= ") + strlen(_tgz_basename);
        _sizeof_dgst_mark = strlen("SHA256()= ") + strlen(_tgz_basename);
        _sizeof_dgst = _sizeof_dgst_mark + SHA256_SIZE*2;
        _sizeof_sig = _sizeof_pkcs_mark + _sizeof_pkcs_modulo;
        free(_sig); _sig = 0;
        free(_dgstD); _dgstD = 0;
        free(_dgstC); _dgstC = 0;
        return true;
    }
    /*@
     * ensures this->_fd==-1;
       ensures this->_sig_off==-1;
       ensures this->_sizeof_sig==-1;
       ensures this->_sizeof_dgst==-1;
       ensures this->_sizeof_pkcs_mark==-1;
       ensures this->_sig_off == -1;
       ensures this->_sig == 0;
       ensures this->_dgstD == 0;
       ensures this->_dgstC == 0;
     */
    void clean()
    {
        if (_fd>-1) close(_fd);

        _fd=-1;
        _sig_off=(off_t)-1;
        _sizeof_sig=(off_t)-1;
        _sizeof_dgst=(off_t)-1;
        _sizeof_pkcs_mark=(off_t)-1;
        _sizeof_dgst_mark=(off_t)-1;
        _sig_off = (off_t)-1;
        free(_sig); _sig = 0;
        free(_dgstD); _dgstD = 0;
        free(_dgstC); _dgstC = 0;
    }
    /*@
     * requires this->_sig==0;
     * requires this->_fd>-1;
     * requires this->_sizeof_sig!=-1);
     * requires this->_sig==0;
     * requires this->_sizeof_pkcs_modulo!=-1;
     * requires this->_sizeof_pkcs_mark!=-1;
     * behaviour failure:
     *   assigns \nothing;
     *   ensures \result==false;
     *   assigns this->_sig_off;
     * behaviour success:
     *   assigns this->_sig_off;
     *   assigns this->_sig;
     *   assigns this->_sig[0..this->_sizeof_pkcs_modulo];
     *   ensures \result==true;
     */
    bool extractSignature()
    {
        assert(_sig_off==(off_t)-1);
        assert(_fd>-1);
        assert(_sizeof_sig!=(off_t)-1);
        assert(_sig==0);
        assert(_sizeof_pkcs_modulo!=(off_t)-1);
        assert(_sizeof_pkcs_mark!=(off_t)-1);

        _sig_off = lseek(_fd, -_sizeof_sig, SEEK_END);
        if (_sig_off==(off_t)-1)
        {
            perror("Failed to seek the signature");
            return false;
        }

        uint8_t *mrk_sig = (uint8_t*)calloc(_sizeof_sig, sizeof(uint8_t));
        int rv = read(_fd, mrk_sig, _sizeof_sig);
        if (rv<=0)
        {
            perror("failed to read signature");
            free(mrk_sig);
            _sig_off=(off_t)-1;
            return false;
        }

        _sig = (uint8_t*)calloc(_sizeof_pkcs_modulo, sizeof(uint8_t));
        memcpy(_sig, mrk_sig + _sizeof_pkcs_mark, _sizeof_pkcs_modulo);

        free(mrk_sig);
        return true;
    }

    bool decryptDigest()
    {
        int len = 0;
        uint8_t *public_key = 0;
        int rv = 0;
        X509_CTX x509_ctx;
        int offset = 0;

        assert(_key_name!=0);
        assert(_dgstD==0);
        assert(_sizeof_pkcs_modulo!=(off_t)-1);
        assert(_sig!=0);

        memset(&x509_ctx,0,sizeof(x509_ctx));

        len = get_file(_key_name, &public_key);
        if (len<=0)
        {
            fprintf(stderr, "failed to open public-key len\n");
            return false;
        }

        rv = asn1_public_key(public_key, &offset, &x509_ctx);
        if (rv!=X509_OK)
        {
            fprintf(stderr, "unable to extract public key\n");
            free(public_key);
            return false;
        }

        _dgstD = (uint8_t*)calloc(_sizeof_pkcs_modulo,sizeof(uint8_t));
        rv = RSA_decrypt(x509_ctx.rsa_ctx, _sig, _dgstD, _sizeof_pkcs_modulo, 0);
        if (rv<=0)
        {
            fprintf(stderr, "Failed to decrypt digest\n");
            free(public_key);
            return false;
        }

        free(public_key);
        RSA_free(x509_ctx.rsa_ctx);
        return true;
    }
    bool computeDigest()
    {
        int rv=0;
        uint8_t buf[512];
        SHA256_CTX sha256_ctx;
        uint8_t sha256_dgst[SHA256_SIZE];

        assert(_fd!=-1);
        assert(_sig_off!=(off_t)-1);
        assert(_dgstC==0);
        assert(_sizeof_dgst_mark!=(off_t)-1);

        memset(buf, 0, sizeof(buf));
        memset(&sha256_ctx, 0, sizeof(sha256_ctx));
        memset(sha256_dgst, 0, sizeof(sha256_dgst));

        if (lseek(_fd, 0, SEEK_SET)==(off_t)-1)
        {
            perror("Failed to seek the signature");
            return false;
        }

        SHA256_Init(&sha256_ctx);
        while (_sig_off>0)
        {
            if (_sig_off<rv||_sig_off< (off_t)sizeof(buf))
                rv=read(_fd,buf,_sig_off);
            else
                rv=read(_fd,buf,sizeof(buf));

            if (rv<0)
            {
                perror("Failed to read signed file");
                return false;
            }

            if (rv==0)
            {
                fprintf(stderr,"eof reached\n");
                return false;
            }
            SHA256_Update(&sha256_ctx, buf, rv);
            _sig_off -= rv;
        }
        SHA256_Final(sha256_dgst, &sha256_ctx);

        _dgstC = (uint8_t*)calloc(_sizeof_dgst + 1 // \0
                                 ,sizeof(uint8_t));

        int o = snprintf((char*)_dgstC, _sizeof_dgst_mark + 1,
                         "SHA256(%s)= ",_tgz_basename);
        for (int i=0; i<SHA256_SIZE; ++i)
        {
            sprintf((char*)_dgstC+o+i*2, "%02x", sha256_dgst[i]);
        }
        return true;
    }
    void printDgst(uint8_t *dgst) const
    {
        assert(_sizeof_dgst!=(off_t)-1);
        for (int i=0; i<_sizeof_dgst; ++i)
        {
            printf("%c",dgst[i]);
        }
        printf("\n");
    }
    bool compareDigests() const
    {
        assert(_dgstD!=0);
        assert(_dgstC!=0);
        assert(_sizeof_dgst!=(off_t)-1);
        for (int i=0;i<_sizeof_dgst; ++i)
        {
            if (_dgstD[i] != _dgstC[i])
            {
                fprintf(stderr, "Verification Failure idx\n");
                printDgst(_dgstD);
                printDgst(_dgstC);
                return false;
            }
        }
        return true;
    }
};


int main(int argc, char* argv[])
{
    if (argc!=3)
    {
        fprintf(stderr, "Usage: verify signed-tgz public-key\n");
        exit(-1);
    }

    const char* tgzfile = argv[1];
    const char* keyfile = argv[2];

    Goopa g = Goopa();

    if ( ! g.Verify(tgzfile, keyfile))
        return -1;

    return 0;
}
