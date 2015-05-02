using daplug.net.Utils;

namespace daplug.net
{
    public class DaplugKeySet
    {

        public enum KeyUsage
        {
            // from https://github.com/Plug-up/daplug-java/blob/master/src/io/daplug/keyset/DaplugKeyset.java
            USAGE_GP = 0x01, /** GlobalPlatform key. */
            USAGE_GP_AUTH = 0x02, /** GlobalPlatform key used for two-ways authentication */
            USAGE_HOTP = 0x03, /** HOTP/OATH key */
            USAGE_HOTP_VALIDATION = 0x04, /** HOTP/OATH key for validation. */
            USAGE_TOTP_VALIDATION = 0x04, /** TOTP/OATH key for validation. */
            USAGE_OTP = 0x05, /** RFU */
            USAGE_ENC = 0x06, /** Encryption Key */
            USAGE_DEC = 0x07, /** Decryption Key */
            USAGE_ENC_DEC = 0x08, /** Encryption + Decryption key */
            USAGE_SAM_CTX = 0x09, /** SAM context encryption key  */
            USAGE_SAM_GP = 0x0A, /** SAM GlobalPlatform usable key  */
            USAGE_SAM_DIV1 = 0x0B, /** SAM provisionable key with mandated diversification by at least one diversifier  */
            USAGE_SAM_DIV2 = 0x0C, /** SAM provisionable key with mandated diversification by at least two diversifiers  */
            USAGE_SAM_CLEAR_EXPORT_DIV1 = 0x0D, /** SAM cleartext exportable key with mandated diversification by at least one diversifier */
            USAGE_SAM_CLEAR_EXPORT_DIV2 = 0x0E, /** SAM cleartext exportable key with mandated diversification by at least two diversifiers  */
            USAGE_IMPORT_EXPORT_TRANSIENT = 0x0F, /** Transient keyset import/export key  */
            USAGE_TOTP_TIME_SRC = 0x10, /** OATH TOTP time source key */
            USAGE_TOTP = 0x11, /** TOTP/OATH key. */
            USAGE_HMAC_SHA1 = 0x12,/** HMAC-SHA1 key. */
            USAGE_HOTP_LOCK = 0x13, /** HOTP/OATH key locking the dongle after each use. */
            USAGE_TOTP_LOCK = 0x14 /** TOTP/OATH key locking the dongle after each use. */
        }

        public byte Version { get; set; }
        public KeyUsage Usage { get; set; }
        public ushort Access { get; set; }
        public byte[] EncKey { get; set; }
        public byte[] MacKey { get; set; }
        public byte[] DeKey { get; set; }


        public DaplugKeySet(byte version, KeyUsage usage, ushort access, string encKey, string macKey, string dekKey)
        {
            this.Version = version;
            this.Usage = usage;
            this.Access = access;
            this.EncKey = Helpers.StringToByteArray(encKey);
            this.MacKey = Helpers.StringToByteArray(macKey);
            this.DeKey = Helpers.StringToByteArray(dekKey);
        }

        public DaplugKeySet(byte version, KeyUsage usage, ushort access, string key)
        {
            this.Version = version;
            this.Usage = usage;
            this.Access = access;
            this.EncKey = Helpers.StringToByteArray(key);
            this.MacKey = Helpers.StringToByteArray(key);
            this.DeKey = Helpers.StringToByteArray(key);
        }

        public DaplugKeySet(byte version, KeyUsage usage, ushort access, byte[] encKey, byte[] macKey, byte[] dekKey)
        {
            this.Version = version;
            this.Usage = usage;
            this.Access = access;
            this.EncKey = encKey;
            this.MacKey = macKey;
            this.DeKey = dekKey;
        }

        public DaplugKeySet(byte version, byte[] encKey, byte[] macKey, byte[] dekKey)
            : this(version, 0, 0, encKey, macKey, dekKey)
        {

        }

        public DaplugKeySet(byte version, byte[] key)
            : this(version, 0, 0, key, key, key)
        {

        }

        public DaplugKeySet(byte version, string key)
            : this(version, 0, 0, Helpers.StringToByteArray(key), Helpers.StringToByteArray(key), Helpers.StringToByteArray(key))
        {

        }
    }
}
