@echo off
echo ========================================
echo WAF Automated Testing
echo ========================================
echo.
echo Make sure the website is running first!
echo Start it with: start_website.bat
echo.
echo Press any key to continue with testing...
pause >nul

python test_waf_website.py

echo.
echo Testing complete!
pause
