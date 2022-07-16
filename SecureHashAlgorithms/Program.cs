using System;
using System.Text;

namespace SecureHashAlgorithms
{
    class Program
    {
        static void Main(string[] args)
        {
            string message = "Nguyễn Quốc Tuấn";
            var sha = new SHA256();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(message));
            var hexString = Convert.ToHexString(hash);
            Console.WriteLine(hexString);

            Console.ReadKey();
        }
    }
}
