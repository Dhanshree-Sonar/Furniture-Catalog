# Furniture-Catalog
There is variety of furniture available in the market now days. If you wish to upgrade your home or fill up an empty house, it is beneficial to know all the options before you go for shopping. This catalog will help you browse through all the options. Product sellers can add furniture data to let people know about new items available in the market.

## Prerequisites

- Install [VirtuaBox](https://www.virtualbox.org/wiki/Download_Old_Builds_5_1)
- Install [Vagrant](https://www.vagrantup.com/downloads.html)
- Download [FSND-Virtual-Machine](https://github.com/udacity/fullstack-nanodegree-vm)

## Initial setup

1. On terminal change directory to your downloads and perform `cd FSND-Virtual-Machine/vagrant`
2. Run `vagrant up`. This command will take a while for the first time.
3. Run `vagrant ssh`
4. On terminal change directory to vagrant directory `cd \vagrant` and place all the files and folders from this repo into it.

## Built with

1. Python
2. Flask framework
3. SQLAlchemy
4. Google OAuth
5. json module to provide endpoint urls
6. httplib2 module to handle HTTP requests

## How to run the furniture catalog

1. On terminal change directory to `vagrant` directory and run `vagrant up`.
2. Run `vagrant ssh`.
3. Run the file application file `python application.py`. It will start the server. Do not close the terminal or stop the server till you are using the catalog.
4. To stop the server press `ctrl + c`.
5. Open the browser window and run `localhost:5000`. It will open the furniture catalog.

## How to use the furniture catalog

- User can browse the catalog without logging-in into the system.
- Home page has a list of categories on sidebar and recently added items with their respective category in work pane.
- User can view the list of items by clicking the category in sidebar or clicking recently added item's category.
- User has to log-in using their Google account in order to perform edit, delete and create operations.
- Logged-in user has option to edit or delete the categories added by him/her. He/she can also add new category to the list.
- When a logged-in user selects category, he/she has option to add new item to that category.
- User can view the item description by clicking the item.
- If user have logged-in and have added the item then, he/she has option to edit or delete the item.

## JSON endpoints

1. For all category names in database: `localhost:5000/categories/JSON`
2. For items in particular category: `localhost:5000/category/<int:cat_id>/items/JSON`
3. For all items in database: `localhost:5000/items/JSON`
3. For particular item details: `localhost:5000/item/<int:item_id>/JSON`
