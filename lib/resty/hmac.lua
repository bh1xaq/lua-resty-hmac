
local str_util = require "resty.string"
local to_hex = str_util.to_hex
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_gc = ffi.gc
local ffi_copy = ffi.copy
local ffi_typeof = ffi.typeof
local C = ffi.C
local setmetatable = setmetatable


local _M = { _VERSION = '0.07' }

local mt = { __index = _M }


ffi.cdef[[
typedef struct engine_st ENGINE;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct hmac_ctx_st HMAC_CTX;
typedef struct evp_md_st EVP_MD;

//OpenSSL 1.0
void HMAC_CTX_init(HMAC_CTX *ctx);
void HMAC_CTX_cleanup(HMAC_CTX *ctx);

//OpenSSL 1.1
HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);

const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
]]

local hashes = {
    MD5 = C.EVP_md5(),
    SHA1 = C.EVP_sha1(),
    SHA256 = C.EVP_sha256(),
    SHA384 = C.EVP_sha384(),
    SHA512 = C.EVP_sha512()
}

_M.ALGOS = hashes

local algo_names = {
    { hashes.MD5, "MD5" },
    { hashes.SHA1, "SHA1" },
    { hashes.SHA256, "SHA256" },
    { hashes.SHA384, "SHA384" },
    { hashes.SHA512, "SHA512" },
}

local function hash_name(hash_algo)
    for i = 1, #algo_names do
        if hash_algo == algo_names[i][1] then
            return algo_names[i][2]
        end
    end
    return nil
end

local buf = ffi_new("unsigned char[64]")
local res_len = ffi_new("unsigned int[1]")
local res_size_len = ffi_new("size_t[1]")

local ctx_new, ctx_free, ctx_init, ctx_update, ctx_final, ctx_reset

local openssl30 = pcall(function ()
    ffi.cdef [[
    typedef struct evp_mac_st EVP_MAC;
    typedef struct evp_mac_ctx_st EVP_MAC_CTX;
    typedef struct ossl_param_st {
        const char *key;
        unsigned int data_type;
        void *data;
        size_t data_size;
        size_t return_size;
    } OSSL_PARAM;

    EVP_MAC *EVP_MAC_fetch(void *libctx, const char *algorithm, const char *properties);
    void EVP_MAC_free(EVP_MAC *mac);
    EVP_MAC_CTX *EVP_MAC_CTX_new(EVP_MAC *mac);
    void EVP_MAC_CTX_free(EVP_MAC_CTX *ctx);
    int EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen, const OSSL_PARAM params[]);
    int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen);
    int EVP_MAC_final(EVP_MAC_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize);
    OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf, size_t bsize);
    OSSL_PARAM OSSL_PARAM_construct_end(void);
    ]]

    local mac = C.EVP_MAC_fetch(nil, "HMAC", nil)
    if mac == nil then
        error("EVP_MAC_fetch HMAC failed")
    end
    C.EVP_MAC_free(mac)
end)

if openssl30 then
    local param_type = ffi_typeof("OSSL_PARAM[2]")

    local function new_params(digest_name)
        local digest = ffi_new("char[?]", #digest_name + 1)
        ffi_copy(digest, digest_name, #digest_name)

        local params = ffi_new(param_type)
        params[0] = C.OSSL_PARAM_construct_utf8_string("digest", digest, 0)
        params[1] = C.OSSL_PARAM_construct_end()

        return params, digest
    end

    ctx_new = function ()
        local mac = C.EVP_MAC_fetch(nil, "HMAC", nil)
        if mac == nil then
            return nil
        end

        local ctx = C.EVP_MAC_CTX_new(mac)
        C.EVP_MAC_free(mac)
        return ctx
    end

    ctx_free = function (ctx)
        C.EVP_MAC_CTX_free(ctx)
    end

    ctx_init = function (ctx, key, hash_algo)
        local digest_name = hash_name(hash_algo)
        if digest_name == nil then
            return nil
        end

        local params, digest = new_params(digest_name)
        if C.EVP_MAC_init(ctx, key, #key, params) == 0 then
            return nil
        end

        return params, digest
    end

    ctx_update = function (ctx, s)
        return C.EVP_MAC_update(ctx, s, #s) == 1
    end

    ctx_final = function (ctx)
        return C.EVP_MAC_final(ctx, buf, res_size_len, 64) == 1, res_size_len[0]
    end

    ctx_reset = function (self)
        return C.EVP_MAC_init(self._ctx, self._key, #self._key, self._params) == 1
    end

else
    local openssl11 = pcall(function ()
        local ctx = C.HMAC_CTX_new()
        C.HMAC_CTX_free(ctx)
    end)

    if openssl11 then
        ffi.cdef [[
        typedef struct evp_md_ctx_st EVP_MD_CTX;
        ]]
        ctx_new = function ()
            return C.HMAC_CTX_new()
        end
        ctx_free = function (ctx)
            C.HMAC_CTX_free(ctx)
        end
    else
        ffi.cdef [[
        typedef struct env_md_ctx_st EVP_MD_CTX;
        struct env_md_ctx_st
        {
            const EVP_MD *digest;
            ENGINE *engine;
            unsigned long flags;
            void *md_data;
            EVP_PKEY_CTX *pctx;
            int (*update)(EVP_MD_CTX *ctx,const void *data,size_t count);
        };

        struct evp_md_st
        {
            int type;
            int pkey_type;
            int md_size;
            unsigned long flags;
            int (*init)(EVP_MD_CTX *ctx);
            int (*update)(EVP_MD_CTX *ctx,const void *data,size_t count);
            int (*final)(EVP_MD_CTX *ctx,unsigned char *md);
            int (*copy)(EVP_MD_CTX *to,const EVP_MD_CTX *from);
            int (*cleanup)(EVP_MD_CTX *ctx);

            int (*sign)(int type, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, void *key);
            int (*verify)(int type, const unsigned char *m, unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, void *key);
            int required_pkey_type[5];
            int block_size;
            int ctx_size;
            int (*md_ctrl)(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
            };

        struct hmac_ctx_st
        {
            const EVP_MD *md;
            EVP_MD_CTX md_ctx;
            EVP_MD_CTX i_ctx;
            EVP_MD_CTX o_ctx;
            unsigned int key_length;
            unsigned char key[128];
        };
        ]]

        local ctx_ptr_type = ffi_typeof("HMAC_CTX[1]")

        ctx_new = function ()
            local ctx = ffi_new(ctx_ptr_type)
            C.HMAC_CTX_init(ctx)
            return ctx
        end
        ctx_free = function (ctx)
            C.HMAC_CTX_cleanup(ctx)
        end
    end

    ctx_init = function (ctx, key, hash_algo)
        return C.HMAC_Init_ex(ctx, key, #key, hash_algo, nil) == 1
    end

    ctx_update = function (ctx, s)
        return C.HMAC_Update(ctx, s, #s) == 1
    end

    ctx_final = function (ctx)
        if C.HMAC_Final(ctx, buf, res_len) == 1 then
            return true, res_len[0]
        end
        return false
    end

    ctx_reset = function (self)
        return C.HMAC_Init_ex(self._ctx, nil, 0, nil, nil) == 1
    end
end


function _M.new(self, key, hash_algo)
    local ctx = ctx_new()
    if ctx == nil then
        return nil
    end

    local _hash_algo = hash_algo or hashes.MD5

    local params, digest = ctx_init(ctx, key, _hash_algo)
    if not params then
        ctx_free(ctx)
        return nil
    end

    ffi_gc(ctx, ctx_free)

    return setmetatable({ _ctx = ctx, _key = key, _params = params, _digest = digest }, mt)
end


function _M.update(self, s)
    return ctx_update(self._ctx, s)
end


function _M.final(self, s, hex_output)

    if s ~= nil then
        if not ctx_update(self._ctx, s) then
            return nil
        end
    end

    local ok, len = ctx_final(self._ctx)
    if ok then
        if hex_output == true then
            return to_hex(ffi_str(buf, len))
        end
        return ffi_str(buf, len)
    end

    return nil
end


function _M.reset(self)
    return ctx_reset(self)
end


return _M
