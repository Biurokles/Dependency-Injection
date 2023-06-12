using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Serwis.Models.Entities;

namespace Serwis.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<User> _signInManager;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(SignInManager<User> signInManager, ILogger<LoginModel> logger)
        {
            _signInManager = signInManager;
            _logger = logger;
        }


        [BindProperty]
        public InputModel DaneWejsciowe { get; set; }

        public IList<AuthenticationScheme> ZewnetrzneLogowania { get; set; }

        public string AdresPowrotu { get; set; }


        [TempData]
        public string KomunikatBledu { get; set; }

    
        public class InputModel
        {

            [Required]
            public string Poświadczenie { get; set; }


            [Required]
            [DataType(DataType.Password)]
            public string Hasło { get; set; }


            [Display(Name = "Zapamiętaj mnie")]
            public bool ZapamiętajMnie { get; set; }
        }

        public async Task OnGetAsync(string adresPowrotu = null)
        {
            if (!string.IsNullOrEmpty(KomunikatBledu))
            {
                ModelState.AddModelError(string.Empty, KomunikatBledu);
            }

            adresPowrotu ??= Url.Content("~/");


            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ZewnetrzneLogowania = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            AdresPowrotu = adresPowrotu;
        }

        public async Task<IActionResult> OnPostAsync(string adresPowrotu = null)
        {
            adresPowrotu ??= Url.Content("~/");

            ZewnetrzneLogowania = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (ModelState.IsValid)
            {
                Microsoft.AspNetCore.Identity.SignInResult wynik;

                var użytkownik = await _signInManager.UserManager.FindByEmailAsync(DaneWejsciowe.Poświadczenie);

                if (użytkownik == null)
                {
                    wynik = await _signInManager.PasswordSignInAsync(DaneWejsciowe.Poświadczenie, DaneWejsciowe.Hasło, DaneWejsciowe.ZapamiętajMnie, lockoutOnFailure: false);
                }
                else
                {
                    wynik = await _signInManager.PasswordSignInAsync(użytkownik.UserName, DaneWejsciowe.Hasło, DaneWejsciowe.ZapamiętajMnie, lockoutOnFailure: false);
                }

                if (wynik.Succeeded)
                {
                    _logger.LogInformation("Użytkownik zalogowany.");
                    return LocalRedirect(adresPowrotu);
                }
                if (wynik.RequiresTwoFactor)
                {
                    return RedirectToPage("./LoginWith2fa", new { AdresPowrotu = adresPowrotu, ZapamiętajMnie = DaneWejsciowe.ZapamiętajMnie });
                }
                if (wynik.IsLockedOut)
                {
                    _logger.LogWarning("Konto użytkownika zostało zablokowane.");
                    return RedirectToPage("./Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Nieprawidłowa próba logowania.");
                    return Page();
                }
            }

       
            return Page();
        }
    }
}
