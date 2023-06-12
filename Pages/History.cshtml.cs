using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Build.Framework;
using Serwis.Interfaces;
using Serwis.Models.Entities;

namespace Serwis.Pages
{
    public class HistoryModel : PageModel
    {
        private readonly IRepository<LeapYearCheck> _leapYearCheckRepository;
        private readonly UserManager<User> _userManager;
        private readonly int _pageSize;

        [BindProperty]
        [Required]
        public int DeleteEntryId { get; set; }

        public IEnumerable<LeapYearCheck> LeapYearChecks { get; set; }
        public int? currentUserId { get; private set; }

        public HistoryModel(IRepository<LeapYearCheck> leapYearCheckRepository, UserManager<User> userManager, IConfiguration configuration)
        {
            _leapYearCheckRepository = leapYearCheckRepository;
            _userManager = userManager;

            _pageSize = (int.TryParse(configuration["HistoryPageSize"], out var temp) ? temp : 20);
        }

        public void OnGet(int? pageIndex)
        {
            currentUserId = int.TryParse(_userManager.GetUserId(User), out var temp) ? temp : null;

            LeapYearChecks = _leapYearCheckRepository.GetAll(x => x.User!)
                .OrderByDescending(x => x.CheckedAt)
                .Skip(((pageIndex ?? 1) - 1) * _pageSize)
                .Take(_pageSize);
        }

        public IActionResult OnPost(int? pageIndex)
        {
            currentUserId = int.TryParse(_userManager.GetUserId(User), out var temp) ? temp : null;

            LeapYearChecks = _leapYearCheckRepository.GetAll(x => x.User!)
            .OrderByDescending(x => x.CheckedAt)
            .Skip(((pageIndex ?? 1) - 1) * _pageSize)
            .Take(_pageSize);

            if (!ModelState.IsValid)
                return Page();

            var entry = _leapYearCheckRepository.Get(x => x.LeapYearCheckId == DeleteEntryId)
            .FirstOrDefault();

            if (entry == null || !User.Identity.IsAuthenticated)
                return Page();

            if (entry.UserId == null || entry.UserId != currentUserId)
                return Page();

            _leapYearCheckRepository.Remove(entry);
            _leapYearCheckRepository.SaveChanges();

            return Page();
        }
    }
}
 