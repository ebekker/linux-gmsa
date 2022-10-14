/* This file is formatted to make it more compatible with PowerShell Add-Type */

namespace GmsaSync
{
    using System;
    using System.IO;
    using System.Security;
    using System.Text;

    /// <summary>
    /// Represents a group-managed service account's password information.
    /// </summary>
    /// <see>https://msdn.microsoft.com/en-us/library/hh881234.aspx</see>
    /// <see>https://raw.githubusercontent.com/MichaelGrafnetter/DSInternals/master/Src/DSInternals.Common/Data/Principals/ManagedPassword.cs</see>
    public class ManagedPassword
    {
        private const int MinimumBlobLength = 6 * sizeof(short) + sizeof(int);

        /// <summary>
        /// Gets the version of the msDS-ManagedPassword binary large object (BLOB).
        /// </summary>
        public short Version
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the current password.
        /// </summary>
        public string CurrentPassword
        {
            get
            {
                return this.SecureCurrentPassword; //.ToUnicodeString();
            }
        }

        /// <summary>
        /// Gets the current password.
        /// </summary>
        public string SecureCurrentPassword
        //public SecureString SecureCurrentPassword
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the previous password.
        /// </summary>
        public string PreviousPassword
        {
            get
            {
                return this.SecurePreviousPassword; //.ToUnicodeString();
            }
        }

        /// <summary>
        /// Gets the previous password.
        /// </summary>
        public string SecurePreviousPassword
        //public SecureString SecurePreviousPassword
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the length of time after which the receiver should requery the password.
        /// </summary>
        public TimeSpan QueryPasswordInterval
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the length of time before which password queries will always return this password value.
        /// </summary>
        public TimeSpan UnchangedPasswordInterval
        {
            get;
            private set;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ManagedPassword"/> class.
        /// </summary>
        /// <param name="blob">
        /// The MSDS-MANAGEDPASSWORD_BLOB, which is a representation
        /// of a group-managed service account's password information.
        /// This structure is returned as the msDS-ManagedPassword constructed attribute.
        /// </param>
        public ManagedPassword(byte[] blob)
        {
            Validator.AssertMinLength(blob, MinimumBlobLength, "blob");
            using (Stream stream = new MemoryStream(blob))
            {
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    // A 16-bit unsigned integer that defines the version of the msDS-ManagedPassword binary large object (BLOB). The Version field MUST be set to 0x0001.
                    this.Version = reader.ReadInt16();
                    // TODO: Test that version == 1

                    // A 16-bit unsigned integer that MUST be set to 0x0000.
                    short reserved = reader.ReadInt16();
                    // TODO: Test that reserved == 0

                    // A 32-bit unsigned integer that specifies the length, in bytes, of the msDS-ManagedPassword BLOB.
                    int length = reader.ReadInt32();
                    Validator.AssertLength(blob, length, "blob");

                    // A 16-bit offset, in bytes, from the beginning of this structure to the CurrentPassword field. The CurrentPasswordOffset field MUST NOT be set to 0x0000.
                    short currentPasswordOffset = reader.ReadInt16();
                    //this.SecureCurrentPassword = blob.ReadSecureWString(currentPasswordOffset);
                    this.SecureCurrentPassword = blob.ReadWString(currentPasswordOffset);

                    // A 16-bit offset, in bytes, from the beginning of this structure to the PreviousPassword field. If this field is set to 0x0000, then the account has no previous password.
                    short previousPasswordOffset = reader.ReadInt16();
                    if (previousPasswordOffset > 0)
                    {
                        //this.SecurePreviousPassword = blob.ReadSecureWString(previousPasswordOffset);
                        this.SecurePreviousPassword = blob.ReadWString(previousPasswordOffset);
                    }

                    // A 16-bit offset, in bytes, from the beginning of this structure to the QueryPasswordInterval field.
                    short queryPasswordIntervalOffset = reader.ReadInt16();
                    long queryPasswordIntervalBinary = BitConverter.ToInt64(blob, queryPasswordIntervalOffset);
                    this.QueryPasswordInterval = TimeSpan.FromTicks(queryPasswordIntervalBinary);

                    // A 16-bit offset, in bytes, from the beginning of this structure to the UnchangedPasswordInterval field.
                    short unchangedPasswordIntervalOffset = reader.ReadInt16();
                    long unchangedPasswordIntervalBinary = BitConverter.ToInt64(blob, unchangedPasswordIntervalOffset);
                    this.UnchangedPasswordInterval = TimeSpan.FromTicks(unchangedPasswordIntervalBinary);
                }
            }
        }
    }

    static class Validator
    {
        public static void AssertNotNull(object value, string paramName)
        {
            if (value == null)
            {
                throw new ArgumentNullException(paramName);
            }
        }

        public static void AssertLength(byte[] value, long length, string paramName)
        {
            AssertNotNull(value, paramName);
            if (value.Length != length)
            {
                throw new ArgumentOutOfRangeException(paramName, value.Length, /*Resources.UnexpectedLengthMessage*/"The length of the input is unexpected.");
            }
        }

        public static void AssertMinLength(byte[] data, int minLength, string paramName)
        {
            AssertNotNull(data, paramName);
            if (data.Length < minLength)
            {
                var exception = new ArgumentOutOfRangeException(paramName, data.Length, /*Resources.InputShorterThanMinMessage*/"The input is shorter than the minimum length.");
                // DEBUG: exception.Data.Add("BinaryBlob", data.ToHex());
                throw exception;
            }
        }
    }

    static class ByteArrayExtensions
    {
        public static string ReadWString(this byte[] buffer, int startIndex)
        {
            Validator.AssertNotNull(buffer, nameof(buffer));
            // TODO: Assert startIndex > 0
            int maxLength = buffer.Length - startIndex;

            // Prepare an empty SecureString that will eventually be returned
            var result = new StringBuilder();

            for (int i = startIndex; i < buffer.Length; i += UnicodeEncoding.CharSize)
            {
                // Convert the next 2 bytes from the byte array into a unicode character
                char c = BitConverter.ToChar(buffer, i);

                if (c == Char.MinValue)
                {
                    // End of string has been reached
                    return result.ToString();
                }

                result.Append(c);
            }

            // If we reached this point, the \0 char has not been found, so throw an exception.
            // TODO: Add a reasonable exception message
            throw new ArgumentException();
        }

        public static SecureString ReadSecureWString(this byte[] buffer, int startIndex)
        {
            Validator.AssertNotNull(buffer, nameof(buffer));
            // TODO: Assert startIndex > 0
            int maxLength = buffer.Length - startIndex;

            // Prepare an empty SecureString that will eventually be returned
            var result = new SecureString();

            for (int i = startIndex; i < buffer.Length; i += UnicodeEncoding.CharSize)
            {
                // Convert the next 2 bytes from the byte array into a unicode character
                char c = BitConverter.ToChar(buffer, i);

                if (c == Char.MinValue)
                {
                    // End of string has been reached
                    return result;
                }

                result.AppendChar(c);
            }

            // If we reached this point, the \0 char has not been found, so throw an exception.
            // TODO: Add a reasonable exception message
            throw new ArgumentException();
        }
    }
}
