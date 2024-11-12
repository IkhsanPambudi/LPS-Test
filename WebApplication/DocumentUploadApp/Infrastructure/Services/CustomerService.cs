public class CustomerService : ICustomerService
{
    private readonly DocumentUploadContext _context;
    private readonly IPasswordHasher _passwordHasher;

    public CustomerService(DocumentUploadContext context, IPasswordHasher passwordHasher)
    {
        _context = context;
        _passwordHasher = passwordHasher;
    }

    public async Task<Customer> RegisterCustomerAsync(string username, string email, string password)
    {
        // Validate password strength
        if (!PasswordIsValid(password))
            throw new Exception("Password does not meet requirements.");

        var passwordHash = _passwordHasher.HashPassword(password);

        var customer = new Customer
        {
            Username = username,
            Email = email,
            PasswordHash = passwordHash,
            CreatedAt = DateTime.UtcNow
        };

        _context.Customers.Add(customer);
        await _context.SaveChangesAsync();
        return customer;
    }

    public async Task<Customer> AuthenticateCustomerAsync(string username, string password)
    {
        var customer = await _context.Customers
            .FirstOrDefaultAsync(c => c.Username == username);

        if (customer == null || !_passwordHasher.VerifyPassword(customer.PasswordHash, password))
            throw new Exception("Invalid username or password.");

        return customer;
    }

    private bool PasswordIsValid(string password)
    { 
        var passwordRegex = new Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-+])[A-Za-z\d!@#$%^&*()\-+]{8,}$");
        return passwordRegex.IsMatch(password);
    }
}
