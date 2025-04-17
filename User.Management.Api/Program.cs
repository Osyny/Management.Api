using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using User.Management.Core.Entities;
using User.Management.Core;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using User.Management.Service.Models;
using User.Management.Service.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    var connetionString = builder.Configuration.GetConnectionString("Default");
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
});

//Add Email Configs
var emailConfig = builder.Configuration.GetSection("EmailConfiguration").Get<EmailConfiguration>();
if(emailConfig != null)
{
    builder.Services.AddSingleton(emailConfig);
}
builder.Services.AddScoped<IEmailService, EmailService>();

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
