using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTTest.Controllers
{
    [Route("api/[controller]")]
    public class TokenController : Controller
    {
        private IConfiguration _config;

        public TokenController(IConfiguration config)
        {
            _config = config;
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult CreateToken([FromBody]LoginModel login)
        {
            IActionResult response = Unauthorized();
            var user = Authenticate(login);

            if (user != null)
            {
                var tokenString = BuildToken(user);
                response = Ok(new { token = tokenString });
            }

            return response;
        }

        private string BuildToken2(UserModel user)
        {
            var secretKey = Encoding.UTF8.GetBytes(_config["JwtSettings:Key"]); // must be 16 character or longer
            var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256Signature);

            var encryptionkey = Encoding.UTF8.GetBytes(_config["JwtSettings:EncryptKey"]); //must be 16 character
            var encryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(encryptionkey), SecurityAlgorithms.Aes128KW, SecurityAlgorithms.Aes128CbcHmacSha256);

            var claims = new List<Claim>
            {
               new Claim(ClaimTypes.Name, "UserName"), //user.UserName
               new Claim(ClaimTypes.NameIdentifier, "123"), //user.Id
            };

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = _config["JwtSettings:Issuer"],//_siteSetting.JwtSettings.Issuer,
                Audience = _config["JwtSettings:Audience"],//_siteSetting.JwtSettings.Audience,
                IssuedAt = DateTime.Now,
                NotBefore = DateTime.Now.AddMinutes(Convert.ToDouble(_config["JwtSettings:AccessTokenExpirationMinutes"])),
                Expires = DateTime.Now.AddMinutes(Convert.ToDouble(_config["JwtSettings:AccessTokenExpirationMinutes"])),
                SigningCredentials = signingCredentials,
                EncryptingCredentials = encryptingCredentials,
                Subject = new ClaimsIdentity(claims)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(descriptor);
            string encryptedJwt = tokenHandler.WriteToken(securityToken);
            return encryptedJwt;
        }

        private string BuildToken(UserModel user)
        {
            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, user.Name),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Birthdate, user.Birthdate.ToString("yyyy-MM-dd")),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtSettings:Key"]));
            var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            //#region Add For Encryption - JWE
            //var encryptionkey = Encoding.UTF8.GetBytes(_config["JwtSettings:EncryptKey"]); //must be 16 character
            //var encryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(encryptionkey), SecurityAlgorithms.Aes128KW, SecurityAlgorithms.Aes128CbcHmacSha256);
            //#endregion

            var token = new JwtSecurityToken(_config["JwtSettings:Issuer"],
              _config["JwtSettings:Audience"],
              claims,
              expires: DateTime.Now.AddMinutes(30),
              signingCredentials: signingCredentials
              );

            return new JwtSecurityTokenHandler().WriteToken(token);

            //var descriptor = new SecurityTokenDescriptor
            //{
            //    Issuer = _config["JwtSettings:Issuer"],
            //    Audience = _config["JwtSettings:Audience"],
            //    IssuedAt = DateTime.Now,
            //    NotBefore = DateTime.Now.AddMinutes(Convert.ToDouble(_config["JwtSettings:AccessTokenExpirationMinutes"])),
            //    Expires = DateTime.Now.AddMinutes(Convert.ToDouble(_config["JwtSettings:AccessTokenExpirationMinutes"])),
            //    SigningCredentials = signingCredentials,
            //    EncryptingCredentials = encryptingCredentials,
            //    Subject = new ClaimsIdentity(claims)
            //};

            //var tokenHandler = new JwtSecurityTokenHandler();
            //var securityToken = tokenHandler.CreateToken(descriptor);
            //string encryptedJwt = tokenHandler.WriteToken(securityToken);
            //return encryptedJwt;
        }

        private UserModel Authenticate(LoginModel login)
        {
            UserModel user = null;

            if (login.Username == "admin" && login.Password == "123")
            {
                user = new UserModel { Name = "Mario Rossi", Email = "mario.rossi@domain.com" };
            }
            if (login.Username == "sbr" && login.Password == "123")
            {
                user = new UserModel { Name = "صابر فرهادی", Email = "sbrfarhadi@yahoo.com", Birthdate = new DateTime(1998, 11, 11) };
            }
            return user;
        }

        public class LoginModel
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }

        private class UserModel
        {
            public string Name { get; set; }
            public string Email { get; set; }
            public DateTime Birthdate { get; set; }
        }
    }
}