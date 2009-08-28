#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <mcrypt.h>

#define MCDBG(x) fprintf(stderr,"%s\n",x); fflush(stderr)

#define ASSIGN_STR_PARAM(sv,str) (str = SvPOK(sv) ? SvPVX(sv) : NULL)
#define ASSIGN_TD_PARAM(sv,td)                              \
   (td = (sv == &PL_sv_undef)                               \
        ? NULL                                              \
        : (SvROK(sv_td) && sv_derived_from(sv_td,"Crypt::Mcrypt::Handle"))    \
            ? INT2PTR(MCRYPT, SvIV((SV *)SvRV(sv_td)))      \
            : NULL)

MODULE = Crypt::Mcrypt PACKAGE = Crypt::Mcrypt::API

PROTOTYPES: DISABLE

MCRYPT
_mcrypt_module_open(sv_algo, sv_adir, sv_mode, sv_mdir)
    SV * sv_algo
    SV * sv_adir
    SV * sv_mode
    SV * sv_mdir
    PREINIT:
        char *algo, *adir, *mode, *mdir;
    CODE:
        ASSIGN_STR_PARAM(sv_algo, algo);
        ASSIGN_STR_PARAM(sv_adir, adir);
        ASSIGN_STR_PARAM(sv_mode, mode);
        ASSIGN_STR_PARAM(sv_mdir, mdir);
        RETVAL = mcrypt_module_open(algo, adir, mode, mdir);
    OUTPUT:
        RETVAL


int
mcrypt_module_close(sv_td)
    SV *sv_td
    PREINIT:
        MCRYPT td;
    CODE:
        if (sv_td == &PL_sv_undef) {
            RETVAL = -1;    /* nonzero indicates failure */
        }
        else if (sv_derived_from(sv_td,"Crypt::Mcrypt::Handle")) {
            IV tmp = SvIV((SV *)SvRV(sv_td));
            td = INT2PTR(MCRYPT,tmp);
            RETVAL = mcrypt_module_close(td);
        }
        else {
            RETVAL = -1;    /* nonzero indicates failure */
        }
    OUTPUT:
        RETVAL


int
mcrypt_module_support_dynamic()


int
_mcrypt_generic_init(sv_td, sv_key, sv_initvec)
    SV *  sv_td
    SV *  sv_key
    SV *  sv_initvec
    PREINIT:
        MCRYPT td;
        STRLEN keylen = 0;
        char *key = NULL, *initvec = NULL;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        if (td) {
            if (SvPOK(sv_key))
                key = SvPV(sv_key,keylen);
    
            if (SvPOK(sv_initvec))
                initvec = SvPV_nolen(sv_initvec);
    
            RETVAL = mcrypt_generic_init(td, key, (int)keylen, initvec);
        }
        else {
            RETVAL = -1;
        }

    OUTPUT:
        RETVAL


int
_mcrypt_generic_deinit(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        if (td) {
            RETVAL = mcrypt_generic_deinit(td);
        }
        else {
            RETVAL = -1;
        }
    OUTPUT:
        RETVAL


int
_mcrypt_generic_end(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        if (td) {
            RETVAL = mcrypt_generic_end(td);
        }
        else {
            RETVAL = -1;
        }
    OUTPUT:
        RETVAL
        


SV *
_mdecrypt_generic(sv_td, sv_ciphertext)
    SV * sv_td
    SV * sv_ciphertext
    PREINIT:
        MCRYPT td;
        STRLEN pt_len;
        int mc_ret;
        char *orig_ciphertext;
        SV *sv_ret;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        if (!td) {
            RETVAL = &PL_sv_undef;
        }
        else {
            /* mcrypt will replace the ciphertext with the plaintext, so we
             * must make a copy first. */

            orig_ciphertext = SvPV(sv_ciphertext, pt_len);
            sv_ret = newSVpvn(orig_ciphertext, pt_len);

            mc_ret = mdecrypt_generic(td, SvPV_nolen(sv_ret), (int)pt_len);
            if (mc_ret == 0) {
                RETVAL = sv_ret;
            }
            else {
             RETVAL = &PL_sv_undef;
            }
        }
    OUTPUT:
        RETVAL


SV *
_mcrypt_generic(sv_td, sv_plaintext)
    SV * sv_td
    SV * sv_plaintext
    PREINIT:
        MCRYPT td;
        STRLEN pt_len;
        int mc_ret;
        char *orig_plaintext;
        SV *sv_ret;
    CODE:
        ASSIGN_TD_PARAM(sv_td, td);
        if (!td) {
            RETVAL = &PL_sv_undef;
        }
        else {
            /* mcrypt will replace the plaintext with the ciphertext, so we
             * must make a copy first. */

            orig_plaintext = SvPV(sv_plaintext, pt_len);
            sv_ret = newSVpvn(orig_plaintext, pt_len);

            mc_ret = mcrypt_generic(td, SvPV_nolen(sv_ret), (int)pt_len);
            if (mc_ret == 0) {
                RETVAL = sv_ret;
            }
            else {
                RETVAL = &PL_sv_undef;
            }
        }

    OUTPUT:
        RETVAL


SV *
_mcrypt_enc_get_state(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
        int size = 0, mc_ret;
        SV *sv_buf;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);

        if (td) {
            /* if size is 0, get_state will set size to the necessary size */
            mc_ret = mcrypt_enc_get_state(td, NULL, &size);
            if (size == 0) {
                RETVAL = &PL_sv_undef;
            }
            else {
                sv_buf = NEWSV(0, size);
                SvPOK_on(sv_buf);
                mc_ret = mcrypt_enc_get_state(td, SvPVX(sv_buf), &size);
    
                if (mc_ret != 0) {
                    sv_2mortal(sv_buf);
                    RETVAL = &PL_sv_undef;
                }
                else {
                    SvCUR_set(sv_buf, size);
                    RETVAL = sv_buf;
                }
            }
        }
        else {
            RETVAL = &PL_sv_undef;
        }
    OUTPUT:
        RETVAL


SV *
_mcrypt_enc_set_state(sv_td, sv_st)
    SV * sv_td
    SV * sv_st
    PREINIT:
        MCRYPT td;
        STRLEN size;
        int mc_ret;
        char *st;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        if (td) {
            if (!SvPOK(sv_st)) {
                RETVAL = &PL_sv_undef;
            }
            else {
                st = SvPV(sv_st, size);
                mc_ret = mcrypt_enc_set_state(td, (void *)st, (int)size);
                RETVAL = newSViv(mc_ret);
            }
        }
        else {
            RETVAL = &PL_sv_undef;
        }
    OUTPUT:
        RETVAL


int
_mcrypt_enc_self_test(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        RETVAL = td ? mcrypt_enc_self_test(td) : -1;
    OUTPUT:
        RETVAL


int
_mcrypt_enc_get_block_size(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        RETVAL = td ? mcrypt_enc_get_block_size(td) : -1;
    OUTPUT:
        RETVAL


int
_mcrypt_enc_get_iv_size(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        RETVAL = td ? mcrypt_enc_get_iv_size(td) : -1;
    OUTPUT:
        RETVAL


int
_mcrypt_enc_get_key_size(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        RETVAL = td ? mcrypt_enc_get_key_size(td) : -1;
    OUTPUT:
        RETVAL


int
_mcrypt_enc_is_block_algorithm(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        RETVAL = td ? mcrypt_enc_is_block_algorithm(td) : -1;
    OUTPUT:
        RETVAL


int
_mcrypt_enc_is_block_mode(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        RETVAL = td ? mcrypt_enc_is_block_mode(td) : -1;
    OUTPUT:
        RETVAL


int
_mcrypt_enc_is_block_algorithm_mode(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        RETVAL = td ? mcrypt_enc_is_block_algorithm_mode(td) : -1;
    OUTPUT:
        RETVAL


int
_mcrypt_enc_mode_has_iv(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        RETVAL = td ? mcrypt_enc_mode_has_iv(td) : -1;
    OUTPUT:
        RETVAL


SV *
_mcrypt_enc_get_algorithms_name(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
        char *name;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        if (td) {
            name = mcrypt_enc_get_algorithms_name(td);
            RETVAL = newSVpv(name,0);
            free(name);
        }
        else {
            RETVAL = &PL_sv_undef;
        }
    OUTPUT:
        RETVAL


SV *
_mcrypt_enc_get_modes_name(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
        char *name;
    CODE:
        ASSIGN_TD_PARAM(sv_td,td);
        if (td) {
            name = mcrypt_enc_get_modes_name(td);
            RETVAL = newSVpv(name,0);
            free(name);
        }
        else {
            RETVAL = &PL_sv_undef;
        }
    OUTPUT:
        RETVAL


void
_mcrypt_enc_get_supported_key_sizes(sv_td)
    SV * sv_td
    PREINIT:
        MCRYPT td;
        int i, num_of_sizes, key_size, *sizes;
    PPCODE:
        ASSIGN_TD_PARAM(sv_td,td);

        if (td) {
            sizes = mcrypt_enc_get_supported_key_sizes(td, &num_of_sizes);
    
            if (sizes == 0) {
                key_size = mcrypt_enc_get_key_size(td);
                for(i = 1; i <= key_size; i++) {
                    XPUSHs(sv_2mortal(newSViv(i)));
                }
            }
            else if (num_of_sizes > 0) {
                for(i = 0; i < num_of_sizes; i++) {
                    XPUSHs(sv_2mortal(newSViv(sizes[i])));
                }
                free(sizes);
            }
            else {
                /* negative */
                croak("mcrypt_enc_get_supported_key_sizes returned "
                    "invalid result");
            }
        }
        else {
            /* nothing -- empty list indicates failure */
        }


void
_mcrypt_list_algorithms(sv_libdir)
    SV * sv_libdir
    PREINIT:
        int i, num_of_algos;
        char **algos, *libdir;
    PPCODE:
        ASSIGN_STR_PARAM(sv_libdir, libdir);

        algos = mcrypt_list_algorithms(libdir, &num_of_algos);

        for(i = 0; i < num_of_algos; i++) {
            XPUSHs(sv_2mortal(newSVpv(algos[i], strlen(algos[i]))));
        }

        mcrypt_free_p(algos, num_of_algos);


void
_mcrypt_list_modes(sv_libdir)
    SV * sv_libdir
    PREINIT:
        int i, num_of_modes;
        char **modes, *libdir;
    PPCODE:
        ASSIGN_STR_PARAM(sv_libdir, libdir);

        modes = mcrypt_list_modes(libdir, &num_of_modes);

        for(i = 0; i < num_of_modes; i++) {
            XPUSHs(sv_2mortal(newSVpv(modes[i], strlen(modes[i]))));
        }

        mcrypt_free_p(modes, num_of_modes);


void
_mcrypt_perror(sv_err)
    SV * sv_err
    CODE:
        mcrypt_perror(SvIV(sv_err));


SV *
_mcrypt_strerror(sv_err)
    SV * sv_err
    PREINIT:
        int    err;
        const char *errstr;
    CODE:
        RETVAL = &PL_sv_undef;
        if (SvIOK(sv_err)) {
            err = SvIV(sv_err);
            errstr = mcrypt_strerror(err);
            if (errstr != NULL) {
                RETVAL = newSVpv(errstr,0);
            }
        }
    OUTPUT:
        RETVAL


int
_mcrypt_module_self_test(sv_algo, sv_adir)
    SV * sv_algo
    SV * sv_adir
    PREINIT:
        char *algo, *adir;
    CODE:
        ASSIGN_STR_PARAM(sv_algo,algo);
        ASSIGN_STR_PARAM(sv_adir,adir);
        RETVAL = mcrypt_module_self_test(algo, adir);
    OUTPUT:
        RETVAL


int
_mcrypt_module_is_block_algorithm(sv_algo, sv_adir)
    SV * sv_algo
    SV * sv_adir
    PREINIT:
        char *algo, *adir;
    CODE:
        ASSIGN_STR_PARAM(sv_algo,algo);
        ASSIGN_STR_PARAM(sv_adir,adir);
        RETVAL = mcrypt_module_is_block_algorithm(algo,adir);
    OUTPUT:
        RETVAL


int
_mcrypt_module_is_block_algorithm_mode(sv_mode, sv_mdir)
    SV * sv_mode
    SV * sv_mdir 
    PREINIT:
        char *mode, *mdir;
    CODE:
        ASSIGN_STR_PARAM(sv_mode,mode);
        ASSIGN_STR_PARAM(sv_mdir,mdir);
        RETVAL = mcrypt_module_is_block_algorithm_mode(mode, mdir);
    OUTPUT:
        RETVAL


int
_mcrypt_module_is_block_mode(sv_mode, sv_mdir)
    SV * sv_mode
    SV * sv_mdir
    PREINIT:
        char *mode, *mdir;
    CODE:
        ASSIGN_STR_PARAM(sv_mode,mode);
        ASSIGN_STR_PARAM(sv_mdir,mdir);
        RETVAL = mcrypt_module_is_block_mode(mode, mdir);
    OUTPUT:
        RETVAL


int
_mcrypt_module_get_algo_key_size(sv_algo, sv_adir)
    SV * sv_algo
    SV * sv_adir
    PREINIT:
        char *algo, *adir;
    CODE:
        ASSIGN_STR_PARAM(sv_algo,algo);
        ASSIGN_STR_PARAM(sv_adir,adir);
        RETVAL = mcrypt_module_get_algo_key_size(algo,adir);
    OUTPUT:
        RETVAL


int
_mcrypt_module_get_algo_block_size(sv_algo, sv_adir)
    SV * sv_algo
    SV * sv_adir
    PREINIT:
        char *algo, *adir;
    CODE:
        ASSIGN_STR_PARAM(sv_algo,algo);
        ASSIGN_STR_PARAM(sv_adir,adir);
        RETVAL = mcrypt_module_get_algo_block_size(algo,adir);
    OUTPUT:
        RETVAL


void
_mcrypt_module_get_algo_supported_key_sizes(sv_algo, sv_adir)
    SV * sv_algo
    SV * sv_adir
    PREINIT:
        int i, num_of_sizes, key_size, *sizes;
        char *algo, *adir;
    PPCODE:
        ASSIGN_STR_PARAM(sv_algo,algo);
        ASSIGN_STR_PARAM(sv_adir,adir);

        sizes = mcrypt_module_get_algo_supported_key_sizes(
            algo, adir, &num_of_sizes);

        if (sizes == 0) {
            key_size = mcrypt_module_get_algo_key_size(
                algo, adir);
            for(i = 1; i <= key_size; i++) {
                XPUSHs(sv_2mortal(newSViv(i)));
            }
        }
        else if (sizes > 0) {
            for(i = 0; i < num_of_sizes; i++) {
                XPUSHs(sv_2mortal(newSViv(sizes[i])));
            }
            free(sizes);
        }
        else {
            /* negative */
            croak("mcrypt_module_get_algo_supported_key_sizes returned invalid result");
        }


int
_mcrypt_module_algorithm_version(sv_algo, sv_adir)
    SV * sv_algo
    SV * sv_adir
    PREINIT:
        char *algo, *adir;
    CODE:
        ASSIGN_STR_PARAM(sv_algo,algo);
        ASSIGN_STR_PARAM(sv_adir,adir);
        RETVAL = mcrypt_module_algorithm_version(algo, adir);
    OUTPUT:
        RETVAL


int
_mcrypt_module_mode_version(sv_mode, sv_mdir)
    SV * sv_mode
    SV * sv_mdir
    PREINIT:
        char *mode, *mdir;
    CODE:
        ASSIGN_STR_PARAM(sv_mode,mode);
        ASSIGN_STR_PARAM(sv_mdir,mdir);
        RETVAL = mcrypt_module_mode_version(mode, mdir);
    OUTPUT:
        RETVAL


SV *
_mcrypt_check_version(sv_v)
    SV * sv_v
    PREINIT:
        char *v;
        const char *p;
    CODE:
        ASSIGN_STR_PARAM(sv_v, v);
        p = mcrypt_check_version(v);
        if (p) {
            RETVAL = newSVpv(p,strlen(p));
        }
        else {
            RETVAL = &PL_sv_undef;
        }
    OUTPUT:
        RETVAL

#/*
########################################################################
#
# only for multithreaded applications
#
#int
#mcrypt_mutex_register(arg0, arg1, arg2, arg3)
#    void ( * mutex_lock ) ( void )    arg0
#    void ( * mutex_unlock ) ( void )    arg1
#    void ( * set_error ) ( const char * )    arg2
#    const char * ( * get_error ) ( void )    arg3
#*/


# constants

char *
LIBMCRYPT_VERSION()

    CODE:
#ifdef LIBMCRYPT_VERSION
    RETVAL = LIBMCRYPT_VERSION;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro LIBMCRYPT_VERSION");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_3DES()

    CODE:
#ifdef MCRYPT_3DES
    RETVAL = MCRYPT_3DES;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_3DES");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_3WAY()

    CODE:
#ifdef MCRYPT_3WAY
    RETVAL = MCRYPT_3WAY;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_3WAY");
#endif

    OUTPUT:
    RETVAL

int
MCRYPT_API_VERSION()

    CODE:
#ifdef MCRYPT_API_VERSION
    RETVAL = MCRYPT_API_VERSION;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_API_VERSION");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_ARCFOUR()

    CODE:
#ifdef MCRYPT_ARCFOUR
    RETVAL = MCRYPT_ARCFOUR;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_ARCFOUR");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_BLOWFISH()

    CODE:
#ifdef MCRYPT_BLOWFISH
    RETVAL = MCRYPT_BLOWFISH;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_BLOWFISH");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_CAST_128()

    CODE:
#ifdef MCRYPT_CAST_128
    RETVAL = MCRYPT_CAST_128;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_CAST_128");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_CAST_256()

    CODE:
#ifdef MCRYPT_CAST_256
    RETVAL = MCRYPT_CAST_256;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_CAST_256");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_CBC()

    CODE:
#ifdef MCRYPT_CBC
    RETVAL = MCRYPT_CBC;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_CBC");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_CFB()

    CODE:
#ifdef MCRYPT_CFB
    RETVAL = MCRYPT_CFB;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_CFB");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_DES()

    CODE:
#ifdef MCRYPT_DES
    RETVAL = MCRYPT_DES;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_DES");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_ECB()

    CODE:
#ifdef MCRYPT_ECB
    RETVAL = MCRYPT_ECB;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_ECB");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_ENIGMA()

    CODE:
#ifdef MCRYPT_ENIGMA
    RETVAL = MCRYPT_ENIGMA;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_ENIGMA");
#endif

    OUTPUT:
    RETVAL

int
MCRYPT_FAILED()

    CODE:
#ifdef MCRYPT_FAILED
    RETVAL = MCRYPT_FAILED;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_FAILED");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_GOST()

    CODE:
#ifdef MCRYPT_GOST
    RETVAL = MCRYPT_GOST;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_GOST");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_LOKI97()

    CODE:
#ifdef MCRYPT_LOKI97
    RETVAL = MCRYPT_LOKI97;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_LOKI97");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_OFB()

    CODE:
#ifdef MCRYPT_OFB
    RETVAL = MCRYPT_OFB;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_OFB");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_RC2()

    CODE:
#ifdef MCRYPT_RC2
    RETVAL = MCRYPT_RC2;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_RC2");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_RIJNDAEL_128()

    CODE:
#ifdef MCRYPT_RIJNDAEL_128
    RETVAL = MCRYPT_RIJNDAEL_128;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_RIJNDAEL_128");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_RIJNDAEL_192()

    CODE:
#ifdef MCRYPT_RIJNDAEL_192
    RETVAL = MCRYPT_RIJNDAEL_192;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_RIJNDAEL_192");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_RIJNDAEL_256()

    CODE:
#ifdef MCRYPT_RIJNDAEL_256
    RETVAL = MCRYPT_RIJNDAEL_256;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_RIJNDAEL_256");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_SAFERPLUS()

    CODE:
#ifdef MCRYPT_SAFERPLUS
    RETVAL = MCRYPT_SAFERPLUS;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_SAFERPLUS");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_SAFER_SK128()

    CODE:
#ifdef MCRYPT_SAFER_SK128
    RETVAL = MCRYPT_SAFER_SK128;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_SAFER_SK128");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_SAFER_SK64()

    CODE:
#ifdef MCRYPT_SAFER_SK64
    RETVAL = MCRYPT_SAFER_SK64;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_SAFER_SK64");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_SERPENT()

    CODE:
#ifdef MCRYPT_SERPENT
    RETVAL = MCRYPT_SERPENT;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_SERPENT");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_STREAM()

    CODE:
#ifdef MCRYPT_STREAM
    RETVAL = MCRYPT_STREAM;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_STREAM");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_TWOFISH()

    CODE:
#ifdef MCRYPT_TWOFISH
    RETVAL = MCRYPT_TWOFISH;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_TWOFISH");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_WAKE()

    CODE:
#ifdef MCRYPT_WAKE
    RETVAL = MCRYPT_WAKE;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_WAKE");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_XTEA()

    CODE:
#ifdef MCRYPT_XTEA
    RETVAL = MCRYPT_XTEA;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_XTEA");
#endif

    OUTPUT:
    RETVAL

char *
MCRYPT_nOFB()

    CODE:
#ifdef MCRYPT_nOFB
    RETVAL = MCRYPT_nOFB;
#else
    croak("Your vendor has not defined the Crypt::Mcrypt::API macro MCRYPT_nOFB");
#endif

    OUTPUT:
    RETVAL
