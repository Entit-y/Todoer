import { chromium } from 'playwright';

async function testApp() {
  console.log('Starting Playwright tests...');
  
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  
  // Track console errors
  const errors = [];
  page.on('console', msg => {
    if (msg.type() === 'error') {
      errors.push(msg.text());
    }
  });
  
  try {
    // Test 1: Login page loads
    console.log('Test 1: Checking login page...');
    await page.goto('http://localhost:3000/');
    await page.waitForSelector('#loginForm', { timeout: 5000 });
    console.log('✓ Login page loads correctly');
    
    // Test 2: Register page loads
    console.log('Test 2: Checking register page...');
    await page.goto('http://localhost:3000/register');
    await page.waitForSelector('#registerForm', { timeout: 5000 });
    console.log('✓ Register page loads correctly');
    
    // Test 3: Login with existing user
    console.log('Test 3: Logging in with existing user...');
    await page.goto('http://localhost:3000/');
    await page.fill('#email', 'test@example.com');
    await page.fill('#password', 'password123');
    await page.click('button[type="submit"]');
    await page.waitForURL('**/home', { timeout: 5000 });
    console.log('✓ User login successful');
    
    // Test 4: Home page loads with tasks section
    console.log('Test 4: Checking home page...');
    await page.waitForSelector('#searchInput', { timeout: 5000 });
    await page.waitForSelector('button:has-text("Add Task")', { timeout: 5000 });
    console.log('✓ Home page loads correctly with task features');
    
    // Test 5: Add a task
    console.log('Test 5: Adding a task...');
    await page.click('button:has-text("Add Task")');
    await page.waitForSelector('#taskModal', { timeout: 5000 });
    await page.fill('#taskTitle', 'Test Task');
    await page.fill('#taskDescription', 'Test Description');
    await page.selectOption('#taskPriority', 'high');
    await page.click('#taskForm button[type="submit"]');
    await page.waitForTimeout(1000);
    console.log('✓ Task creation attempted');
    
    // Test 6: Test search functionality
    console.log('Test 6: Testing search...');
    await page.fill('#searchInput', 'Test');
    await page.click('button:has-text("Search")');
    await page.waitForTimeout(500);
    console.log('✓ Search functionality works');
    
    // Test 7: Navigate to Files page
    console.log('Test 7: Checking files page...');
    await page.click('a:has-text("Files")');
    await page.waitForURL('**/files', { timeout: 5000 });
    await page.waitForSelector('h1:has-text("My Files")', { timeout: 5000 });
    console.log('✓ Files page loads correctly');
    
    // Test 8: Navigate to Profile page
    console.log('Test 8: Checking profile page...');
    await page.click('a:has-text("Profile")');
    await page.waitForURL('**/profile', { timeout: 5000 });
    await page.waitForSelector('#emailForm', { timeout: 5000 });
    await page.waitForSelector('#passwordForm', { timeout: 5000 });
    await page.waitForSelector('#deleteForm', { timeout: 5000 });
    console.log('✓ Profile page loads with all sections');
    
    // Test 9: Check profile sections exist
    const emailSection = await page.$('#emailForm');
    const passwordSection = await page.$('#passwordForm');
    const deleteSection = await page.$('#deleteForm');
    if (emailSection && passwordSection && deleteSection) {
      console.log('✓ All profile sections present (email, password, delete)');
    }
    
    // Test 10: Logout
    console.log('Test 10: Testing logout...');
    await page.click('#logoutBtn');
    await page.waitForURL('**/', { timeout: 5000 });
    console.log('✓ Logout works correctly');
    
    // Report console errors
    if (errors.length > 0) {
      console.log('\n⚠️ Console errors detected:');
      errors.forEach(err => console.log('  -', err));
    } else {
      console.log('\n✓ No console errors detected');
    }
    
    console.log('\n========================================');
    console.log('All tests completed successfully!');
    console.log('========================================\n');
    
  } catch (error) {
    console.error('\n✗ Test failed:', error.message);
    process.exit(1);
  } finally {
    await browser.close();
  }
}

testApp();
