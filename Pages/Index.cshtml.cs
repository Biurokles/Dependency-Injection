using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Serwis.Pages.Forms;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using NuGet.Protocol.Core.Types;
using Serwis.Interfaces;
using Serwis.Models.Entities;

namespace Serwis.Pages
{
    public class IndexModel : PageModel
    {
        [BindProperty]
        public DateForm DateForm { get; set; }

        public string Message => GetMessage();
        private readonly UserManager<User> _userManager;
        private readonly IRepository<LeapYearCheck> _leapYearCheckRepository;

        public IndexModel(UserManager<User> userManager, IRepository<LeapYearCheck> leapYearCheckRepository)
        {
            _userManager = userManager;
            _leapYearCheckRepository = leapYearCheckRepository;
        }

        private string GetMessage()
        {
            bool isGirl = false;
            var isLeap = DateTime.IsLeapYear(DateForm.Year);

            if (DateForm.Name == null)
            {
                return $"{DateForm.Year} {(isLeap ? string.Empty : "nie")} był rokiem przestępnym";
            }

            if (DateForm.Name.Last() == 'a')
            {
                isGirl = true;
            }
            
            return $"{DateForm.Name} urodził{(isGirl ? "a" : string.Empty)} się w {DateForm.Year} roku. To {(DateTime.IsLeapYear(DateForm.Year) ? string.Empty : "nie") }był rok przestępny.";
        }

        public IActionResult OnPost()
        {
            if(!ModelState.IsValid)
            {
                return Page();

            }

            var isLeap = DateTime.IsLeapYear(DateForm.Year);

            int? userId = int.TryParse(_userManager.GetUserId(User), out var temp) ? temp : null;

            var entity = new LeapYearCheck
            {
                UserId = userId,
                Name = DateForm.Name,
                Year = DateForm.Year,
                IsLeap = isLeap,
                CheckedAt = DateTime.Now
            };

            _leapYearCheckRepository.Add(entity);
            _leapYearCheckRepository.SaveChanges();

            return Page();
        }

        public void OnGet()
        {

        }
    }
}