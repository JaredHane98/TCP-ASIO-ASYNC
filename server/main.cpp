

#include "TCPServerManager.hpp"
#include "ItemList.hpp"

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>










int main(void)
{
    // create a list of basic items
    std::shared_ptr<StreamableItemList> list = StreamableItemList::createItemList();
    list->addStoredItem("Courtney", {53, 32, 95}, {95.34, 597.794}, 45, 5346345, false);
    list->addStoredItem("Joe", {94, 36, 93}, {9535.8743, 1.42, 953.42}, 90, 634, true);
    list->addStoredItem("Meg", {93, 95, 76}, {93.63, 1.42, 100.1}, 54, 92963, false);
    list->addStoredItem("Steve", {4, 16, 17}, {063, 1.42, 53.3, 69}, 56, 99634, false);

    
    TcpServerManager server("server.pem", "server.pem", "dh4096.pem", 1234, list);
    server.run();
    return 0;
}








