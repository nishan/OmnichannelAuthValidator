using System;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
namespace ConsoleApp2
{
    /// <summary>
    /// Class used to implement <c>string</c> related functions.
    /// </summary>
    public static class StringExtensions
    {
        /// <summary>
        /// Sanitizes string with special characters and emojis and replace with empty string
        /// </summary>
        /// <param name="input">Input string</param>
        /// <returns>Sanitized text</returns>
        public static string Sanitize(this string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return input;
            }
            try
            {
                input = SanitizeEmojis(input);
                var specialChars = @"[^\w\s]";
                input = Regex.Replace(input, specialChars, string.Empty,
                                        RegexOptions.None, TimeSpan.FromSeconds(1.5));
            }
            catch
            {
                // don't fail if regex fails
            }
            return string.IsNullOrEmpty(input) ? input : input.Trim();
        }
        /// <summary>
        /// Sanitizes emojis
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string SanitizeEmojis(this string input)
        {
            if (StringHasSurrogates(input))
            {
                var stNew = SanitizeEmojiText(input);
                return stNew;
            }
            return input;
        }
        private static bool StringHasSurrogates(string input)
        {
            foreach (var c in input)
            {
                if (char.IsSurrogate(c))
                {
                    return true;
                }
            }
            return false;
        }
        public static string SanitizeEmojiText(string message)
        {
            if (!StringHasSurrogates(message))
            {
                return message;
            }
            var sb = new StringBuilder();
            var charEnum = StringInfo.GetTextElementEnumerator(message);
            while (charEnum.MoveNext())
            {
                var text = charEnum.GetTextElement();
                if (text.Length == 1)
                {
                    sb.AppendFormat(text);
                }
            }
            return sb.ToString();
        }
    }
}

