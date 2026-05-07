using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using ServiSeg.Data;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// Configuracion del contexto - Paso 3

builder.Services.AddDbContext<AppDBContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("ServiSegContext"),
    sqlServerOptionsAction: sqlOptions =>
    {
        sqlOptions.EnableRetryOnFailure(
            maxRetryCount: 5,
            maxRetryDelay: TimeSpan.FromSeconds(30),
            errorNumbersToAdd: null
            );
    }
    ));

// Configuracion de dependencias

// Inyeccion de clases de indentity: rol y usuario - paso 6

builder.Services.AddIdentity<IdentityUser, IdentityRole>(options => 
{ 
    // Politica de passwords
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 7;
    options.Password.RequiredUniqueChars = 7;
    // Politica de bloqueos
    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromHours(8);
    // Politica de registro
})
    .AddEntityFrameworkStores<AppDBContext>()
    .AddDefaultTokenProviders();

// Configurar Authenticacion, usando JwtBearer - paso 7

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        var jwtIssuer = builder.Configuration.GetSection("Jwt:Issuer").ToString();
        var jwtAudience = builder.Configuration.GetSection("Jwt:Audience").ToString();
        var jwtKey = Encoding.ASCII.GetBytes(builder.Configuration.GetSection("Jwt:Key").Value);

        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false, 
            ValidateAudience = false, 
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(jwtKey)
        };
    });

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
//builder.Services.AddSwaggerGen();

// Paso 18

// Agregar autorizacion a Swagger

builder.Services.AddSwaggerGen(c =>
{
    // Especificar documentacion a swagger
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "ServiSeg App",
        Version = "v1"
    });

    // Definir el esquema de seguridad para Bearer
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Ingrese 'Bearer' [espacio] y luego su token JWT en el campo de texto."
    });

    // Requerir el esquema de seguridad para todas las operaciones
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
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
            new string[] {}
        }
    });
});

// Construccion

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Definir el uso de autenticacion
app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
