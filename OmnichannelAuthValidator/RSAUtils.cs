using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace OmnichannelAuthValidator
{
    class RSAUtils
    {
        public static RSACryptoServiceProvider DecodePublicKey(byte[] publicKeyBytes)
        {
            MemoryStream ms = new MemoryStream(publicKeyBytes);
            BinaryReader rd = new BinaryReader(ms);
            byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];

            try
            {
                byte byteValue;
                ushort shortValue;

                shortValue = rd.ReadUInt16();

                switch (shortValue)
                {
                    case 0x8130:
                        rd.ReadByte();
                        break;
                    case 0x8230:
                        rd.ReadInt16();
                        break;
                    default:
                        return null;
                }

                seq = rd.ReadBytes(15);
                if (!Helpers.CompareBytearrays(seq, SeqOID))
                {
                    return null;
                }

                shortValue = rd.ReadUInt16();
                if (shortValue == 0x8103)
                {
                    rd.ReadByte();
                }
                else if (shortValue == 0x8203)
                {
                    rd.ReadInt16();
                }
                else
                {
                    return null;
                }

                byteValue = rd.ReadByte();
                if (byteValue != 0x00)
                {
                    return null;
                }

                shortValue = rd.ReadUInt16();
                if (shortValue == 0x8130)
                {
                    rd.ReadByte();
                }
                else if (shortValue == 0x8230)
                {
                    rd.ReadInt16();
                }
                else
                {
                    return null;
                }

                CspParameters parms = new CspParameters();
                parms.Flags = CspProviderFlags.NoFlags;
                parms.KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant();
                parms.ProviderType = ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1))) ? 0x18 : 1;

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(parms);
                RSAParameters rsAparams = new RSAParameters();

                rsAparams.Modulus = rd.ReadBytes(Helpers.DecodeIntegerSize(rd));

                RSAParameterTraits traits = new RSAParameterTraits(rsAparams.Modulus.Length * 8);

                rsAparams.Modulus = Helpers.AlignBytes(rsAparams.Modulus, traits.size_Mod);
                rsAparams.Exponent = Helpers.AlignBytes(rd.ReadBytes(Helpers.DecodeIntegerSize(rd)), traits.size_Exp);

                rsa.ImportParameters(rsAparams);
                return rsa;
            }
            catch (Exception ex)
            {
             // LiveChatConnectorTelemetry.Exception(LiveChatConnectorTelemetry.PUBLIC_KEY_DECODE_ERROR, "Error while trying to decode the public key", ex);
            }
            finally
            {
                rd.Close();
            }
            return null;
        }

        internal class Helpers
        {
            public static bool CompareBytearrays(byte[] a, byte[] b)
            {
                if (a.Length != b.Length)
                    return false;
                int i = 0;
                foreach (byte c in a)
                {
                    if (c != b[i])
                        return false;
                    i++;
                }
                return true;
            }

            public static byte[] AlignBytes(byte[] inputBytes, int alignSize)
            {
                int inputBytesSize = inputBytes.Length;

                if ((alignSize != -1) && (inputBytesSize < alignSize))
                {
                    byte[] buf = new byte[alignSize];
                    for (int i = 0; i < inputBytesSize; ++i)
                    {
                        buf[i + (alignSize - inputBytesSize)] = inputBytes[i];
                    }
                    return buf;
                }
                else
                {
                    return inputBytes;
                }
            }

            public static int DecodeIntegerSize(System.IO.BinaryReader rd)
            {
                byte byteValue;
                int count;

                byteValue = rd.ReadByte();
                if (byteValue != 0x02) return 0;

                byteValue = rd.ReadByte();
                if (byteValue == 0x81)
                {
                    count = rd.ReadByte();
                }
                else if (byteValue == 0x82)
                {
                    byte hi = rd.ReadByte(); byte lo = rd.ReadByte();
                    count = BitConverter.ToUInt16(new[] { lo, hi }, 0);
                }
                else
                {
                    count = byteValue;
                }

                while (rd.ReadByte() == 0x00)
                {
                    count -= 1;
                }
                rd.BaseStream.Seek(-1, System.IO.SeekOrigin.Current);

                return count;
            }
        }

        internal class RSAParameterTraits
        {
            public RSAParameterTraits(int modulusLengthInBits)
            {
                int assumedLength = -1;
                double logbase = Math.Log(modulusLengthInBits, 2);
                if (logbase == (int)logbase)
                {
                    assumedLength = modulusLengthInBits;
                }
                else
                {
                    assumedLength = (int)(logbase + 1.0);
                    assumedLength = (int)(Math.Pow(2, assumedLength));
                    System.Diagnostics.Debug.Assert(false);
                }

                switch (assumedLength)
                {
                    case 512:
                        this.size_Mod = 0x40;
                        this.size_Exp = -1;
                        this.size_D = 0x40;
                        this.size_P = 0x20;
                        this.size_Q = 0x20;
                        this.size_DP = 0x20;
                        this.size_DQ = 0x20;
                        this.size_InvQ = 0x20;
                        break;
                    case 1024:
                        this.size_Mod = 0x80;
                        this.size_Exp = -1;
                        this.size_D = 0x80;
                        this.size_P = 0x40;
                        this.size_Q = 0x40;
                        this.size_DP = 0x40;
                        this.size_DQ = 0x40;
                        this.size_InvQ = 0x40;
                        break;
                    case 2048:
                        this.size_Mod = 0x100;
                        this.size_Exp = -1;
                        this.size_D = 0x100;
                        this.size_P = 0x80;
                        this.size_Q = 0x80;
                        this.size_DP = 0x80;
                        this.size_DQ = 0x80;
                        this.size_InvQ = 0x80;
                        break;
                    case 4096:
                        this.size_Mod = 0x200;
                        this.size_Exp = -1;
                        this.size_D = 0x200;
                        this.size_P = 0x100;
                        this.size_Q = 0x100;
                        this.size_DP = 0x100;
                        this.size_DQ = 0x100;
                        this.size_InvQ = 0x100;
                        break;
                    default:
                        System.Diagnostics.Debug.Assert(false); break;
                }
            }

            public int size_Mod = -1;
            public int size_Exp = -1;
            public int size_D = -1;
            public int size_P = -1;
            public int size_Q = -1;
            public int size_DP = -1;
            public int size_DQ = -1;
            public int size_InvQ = -1;
        }

    }
}
