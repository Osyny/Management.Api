using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using User.Management.Core.Entities;
using User.Management.Core;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using User.Management.Service.Models;
using User.Management.Service.Services;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

var configuration = (IConfiguration)builder.Configuration;

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    var connetionString = configuration.GetConnectionString("Default");
    options.UseMySql(connetionString, ServerVersion.AutoDetect(connetionString));
});

// For Identity
builder.Services
 .AddIdentity<ApplicationUser, IdentityRole>()
 .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Add Config for Required Email
builder.Services.Configure<IdentityOptions>(options =>  options.SignIn.RequireConfirmedEmail = true);

// Adding Authentification
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(opt =>
{
    opt.SaveToken = true;
    opt.RequireHttpsMetadata = false;
    opt.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidAudience = configuration["JWT:ValidAudience"],
        ValidIssuer = configuration["JWT:ValidIssuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]))
    };
});

//Add Email Configs
var emailConfig = configuration.GetSection("EmailConfiguration").Get<EmailConfiguration>();
if(emailConfig != null)
{
    builder.Services.AddSingleton(emailConfig);
}
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IUserManagement, UserManagement>();

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth API", Version = "v1" });
    option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
    {
        In = ParameterLocation.Header,
        Description = "Please enter a valid token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer",
    });
    option.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[]{}
        }
    });
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
