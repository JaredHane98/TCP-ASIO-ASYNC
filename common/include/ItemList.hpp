#ifndef ITEM_HPP
#define ITEM_HPP
#include <mutex>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <memory>



class StreamableBase
{
public:
    virtual std::ostream& load(std::ostream& os) = 0;
    virtual std::istream& save(std::istream& is) = 0;
}; 


class BasicItem
{
private:
    std::mutex m_mutex;
    std::string m_name;
    std::vector<char> m_char_data;
    std::vector<float> m_float_data;
    int m_age;
    int m_ssn;
    bool m_married;
public:
    BasicItem(const std::string& name, const std::vector<char>& char_data, const std::vector<float>& float_data, const int age, const int ssn, const bool married)
        : m_mutex(), m_name(name), m_char_data(char_data), m_float_data(float_data), m_age(age), m_ssn(ssn), m_married(married)
    {}
    BasicItem(const BasicItem& item)
        : m_mutex(), m_name(item.m_name), m_char_data(item.m_char_data), m_float_data(item.m_float_data), m_age(item.m_age), m_ssn(item.m_ssn), m_married(item.m_married)
    {}
    BasicItem()
        : m_mutex(), m_name(), m_char_data(), m_float_data(), m_age(), m_ssn(), m_married()
    {}
    ~BasicItem()
    {}

    friend std::ostream &operator<<(std::ostream& out, BasicItem& item)
    {
        std::lock_guard<std::mutex> guard(item.m_mutex);
        const auto num_chars = item.m_char_data.size();
        const auto num_floats = item.m_float_data.size();

        out << item.m_name << ' ';
        out << item.m_age << ' ';
        out << item.m_ssn << ' ';
        out << item.m_married << ' '; 

        // writing the arrays

        // first character array
        out << num_chars << ' '; 
        for(size_t i = 0; i < num_chars; i++)
            out << item.m_char_data[i] << ' ';

        // next float array
        out << num_floats << ' '; 
        for(size_t i = 0; i < num_floats; i++)
            out << item.m_float_data[i] << ' ';
            
        return out;
    }

    friend std::istream &operator>>(std::istream& is, BasicItem& item)
    {
        std::lock_guard<std::mutex> guard(item.m_mutex);
        size_t num_chars;
        size_t num_floats;

        is >> item.m_name;
        is >> item.m_age;
        is >> item.m_ssn;
        is >> item.m_married;

        // reading the arrays

        // first character array
        is >> num_chars; 
        item.m_char_data.resize(num_chars);

        // chars are tricky because of noskipws and space is a valid value
        is.ignore(1, ' '); // ignore first space
        for(size_t i = 0; i < num_chars; i++)
        {
            int character = is.get(); // get the character
            int ignore = is.get();    // ignore next character
            item.m_char_data[i] = (char)character;
        }

        // now float array. rather simple
        is >> num_floats; 
        item.m_float_data.resize(num_floats);
        for(size_t i = 0; i < num_floats; i++)
            is >> item.m_float_data[i];
            
        return is;
    }
};





class StreamableItemList : public StreamableBase
{
private:
    std::mutex m_mutex;
    std::vector<BasicItem> m_stored_items;
    std::vector<BasicItem> m_loaded_items;

    StreamableItemList()
        : m_mutex(), m_stored_items(), m_loaded_items()
    {}
public:
    ~StreamableItemList()
    {}

    StreamableItemList(const StreamableItemList&) = delete;
    StreamableItemList(StreamableItemList&&) = delete;

    void addStoredItem(const std::string& name, const std::vector<char>& char_data, const std::vector<float>& float_data, const int age, const int ssn, const bool married)
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        m_stored_items.push_back(BasicItem(name, char_data, float_data, age, ssn, married));
    }

    void outputLoadedItems()
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        for(size_t i = 0; i < m_loaded_items.size(); i++)
            std::cout << m_loaded_items[i];
    }

    static std::shared_ptr<StreamableItemList> createItemList()
    {
        struct StreamableItemListShared : public StreamableItemList {};
        return std::make_shared<StreamableItemListShared>();
    }

    virtual std::ostream& load(std::ostream& os) override
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        const auto items_size = m_stored_items.size();
        os << items_size;

        for(size_t i = 0; i < items_size; i++)
            os << m_stored_items[i];
        return os;
    }

    virtual std::istream& save(std::istream& is) override
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        size_t loaded_items_size;
        is >> loaded_items_size; 

        m_loaded_items.resize(loaded_items_size);

        for(size_t i = 0; i < loaded_items_size; i++)
            is >> m_loaded_items[i];
        return is;
    }
};








#endif // ITEM_HPP