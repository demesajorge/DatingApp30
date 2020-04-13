using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using DatingApp.API.Dtos;
using DatingApp.API.Modules;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]    // this allow to use all the features of the "User" class like the required atributes

    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        public readonly  IConfiguration _config;

        private readonly IMapper _mapper;
        public AuthController(IAuthRepository repo, IConfiguration config, IMapper mapper)
        {
            _repo   = repo;
            _config = config;
            _mapper = mapper;
        }
        
        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto) 
        {
            #region Optional validate request
                
            //  
            // if (userForRegisterDto.Username == "")
            // {
            //     return BadRequest("You have to provide a Username");
            // }
            
            // if (userForRegisterDto.Password == "")
            // {
            //     return BadRequest("You have to provide a Password");
            // }

            // if (!ModelState.IsValid) // this is another way to do it is you dont want to use the apicontroler
            // {
            //     return BadRequest(ModelState);
            // }
            #endregion

            userForRegisterDto.Username = userForRegisterDto.Username.ToLower();
            if (await _repo.UserExists(userForRegisterDto.Username))            
                return BadRequest("Username alredy exists");

            // var userToCreate = new User
            // {
            //     Username = userForRegisterDto.Username
            // };
            var userToCreate = _mapper.Map<User>(userForRegisterDto);

            var createUser = await _repo.Register(userToCreate,userForRegisterDto.Password);

            var userToReturn = _mapper.Map<UserForDetailedDto>(createUser);
            //return StatusCode(201);//we have to return the route of the new user
            return CreatedAtRoute("GetUser",new {controller = "Users", id = createUser.Id}, userToReturn);
        }   

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            //throw new Exception("Computer says no!");
            var userFromRepo = await _repo.Login(userForLoginDto.Username.ToLower(), userForLoginDto.Password);
            if (userFromRepo == null)
                return Unauthorized();

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.Username)
                
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8
            .GetBytes(_config.GetSection("AppSettings:Token").Value)); //local firm in order to create the token

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescriptor =  new SecurityTokenDescriptor  //creating the token
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);

            var user = _mapper.Map<UserForListDto>(userFromRepo);
            // you can validate the token in https://jwt.io/ so  you have to be careful with the info in it
            return Ok(new {
                token = tokenHandler.WriteToken(token),
                user
            });

        }
    }
}